// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Push info and metrics to zedcloud

package zedagent

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/eriknordmark/netlink"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/cmd/vaultmgr"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netclone"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	psutilnet "github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
)

// Report disk usage for these paths
var reportDiskPaths = []string{
	"/",
	types.IdentityDirname,
	types.PersistDir,
}

// Report directory usage for these paths
var reportDirPaths = []string{
	types.PersistDir + "/downloads",
	types.PersistDir + "/img",
	types.PersistDir + "/tmp",
	types.PersistDir + "/log",
	types.PersistDir + "/rsyslog",
	types.PersistDir + "/config",
	types.PersistDir + "/status",
	types.PersistDir + "/certs",
	types.PersistDir + "/checkpoint",
}

// Application-related files live here; includes downloads and verifications in progress
var appPersistPaths = []string{
	types.PersistDir + "/img",
	types.AppImgDirname,
}

func encodeErrorInfo(et types.ErrorAndTime) *info.ErrorInfo {
	if et.ErrorTime.IsZero() {
		// No Success / Error to report
		return nil
	}
	errInfo := new(info.ErrorInfo)
	errInfo.Description = et.Error
	protoTime, err := ptypes.TimestampProto(et.ErrorTime)
	if err == nil {
		errInfo.Timestamp = protoTime
	} else {
		log.Errorf("Failed to convert timestamp (%+v) for ErrorStr (%s) "+
			"into TimestampProto. err: %s", et.ErrorTime, et.Error, err)
	}
	return errInfo
}

// We reuse the info.ErrorInfo to pass both failure and success. If success
// the Description is left empty
func encodeTestResults(tr types.TestResults) *info.ErrorInfo {
	errInfo := new(info.ErrorInfo)
	var timestamp time.Time
	if tr.HasError() {
		timestamp = tr.LastFailed
		errInfo.Description = tr.LastError
	} else {
		timestamp = tr.LastSucceeded
	}
	if !timestamp.IsZero() {
		protoTime, err := ptypes.TimestampProto(timestamp)
		if err == nil {
			errInfo.Timestamp = protoTime
		} else {
			log.Errorf("Failed to convert timestamp (%+v) for ErrorStr (%s) "+
				"into TimestampProto. err: %s", timestamp, tr.LastError, err)
		}
	}
	return errInfo
}

// Run a periodic post of the metrics
func metricsTimerTask(ctx *zedagentContext, handleChannel chan interface{}) {
	iteration := 0
	log.Infoln("starting report metrics timer task")
	publishMetrics(ctx, iteration)

	interval := time.Duration(ctx.globalConfig.GlobalValueInt(types.MetricInterval)) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			iteration += 1
			publishMetrics(ctx, iteration)
			pubsub.CheckMaxTimeTopic(agentName+"metrics", "publishMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)
	}
}

// Called when globalConfig changes
// Assumes the caller has verifier that the interval has changed
func updateMetricsTimer(metricInterval uint32, tickerHandle interface{}) {

	if tickerHandle == nil {
		log.Warnf("updateMetricsTimer: no metricsTickerHandle yet")
		return
	}
	interval := time.Duration(metricInterval) * time.Second
	log.Infof("updateMetricsTimer() change to %v", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(tickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timout since timer could have decreased
	flextimer.TickNow(tickerHandle)
}

// Key is device UUID for host and app instance UUID for app instances
// Returns DomainMetric
func lookupDomainMetric(ctx *zedagentContext, uuidStr string) *types.DomainMetric {
	sub := ctx.getconfigCtx.subDomainMetric
	m, _ := sub.Get(uuidStr)
	if m == nil {
		log.Infof("lookupDomainMetric(%s) not found", uuidStr)
		return nil
	}
	metric := m.(types.DomainMetric)
	return &metric
}

func lookupAppContainerMetric(ctx *zedagentContext, uuidStr string) *types.AppContainerMetrics {
	sub := ctx.subAppContainerMetrics
	m, _ := sub.Get(uuidStr)
	if m == nil {
		return nil
	}
	metric := m.(types.AppContainerMetrics)
	return &metric
}

func publishMetrics(ctx *zedagentContext, iteration int) {

	var ReportMetrics = &metrics.ZMetricMsg{}

	startPubTime := time.Now()

	ReportDeviceMetric := new(metrics.DeviceMetric)
	ReportDeviceMetric.Memory = new(metrics.MemoryMetric)
	ReportDeviceMetric.CpuMetric = new(metrics.AppCpuMetric)

	ReportMetrics.DevID = *proto.String(zcdevUUID.String())
	ReportZmetric := new(metrics.ZmetricTypes)
	*ReportZmetric = metrics.ZmetricTypes_ZmDevice

	ReportMetrics.AtTimeStamp = ptypes.TimestampNow()

	info, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s", err)
	}
	log.Debugf("uptime %d = %d days",
		info.Uptime, info.Uptime/(3600*24))
	log.Debugf("Booted at %v", time.Unix(int64(info.BootTime), 0).UTC())

	// Note that uptime is seconds we've been up. We're converting
	// to a timestamp. That better not be interpreted as a time since
	// the epoch
	uptime, _ := ptypes.TimestampProto(
		time.Unix(int64(info.Uptime), 0).UTC())
	ReportDeviceMetric.CpuMetric.UpTime = uptime

	// Memory related info for the device
	var totalMemory, freeMemory uint64
	sub := ctx.getconfigCtx.subHostMemory
	m, _ := sub.Get("global")
	if m != nil {
		metric := m.(types.HostMemory)
		totalMemory = metric.TotalMemoryMB
		freeMemory = metric.FreeMemoryMB
	}
	// total_memory and free_memory is in MBytes
	used := totalMemory - freeMemory
	ReportDeviceMetric.Memory.UsedMem = uint32(used)
	ReportDeviceMetric.Memory.AvailMem = uint32(freeMemory)
	var usedPercent float64
	if totalMemory != 0 {
		usedPercent = float64(100) * float64(used) / float64(totalMemory)
	}
	ReportDeviceMetric.Memory.UsedPercentage = usedPercent
	ReportDeviceMetric.Memory.AvailPercentage = (100.0 - (usedPercent))
	log.Debugf("Device Memory from xl info: %v %v %v %v",
		ReportDeviceMetric.Memory.UsedMem,
		ReportDeviceMetric.Memory.AvailMem,
		ReportDeviceMetric.Memory.UsedPercentage,
		ReportDeviceMetric.Memory.AvailPercentage)

	// Use the network metrics from zedrouter subscription
	// Only report stats for the ports in DeviceNetworkStatus
	labelList := types.ReportLogicallabels(*deviceNetworkStatus)
	for _, label := range labelList {
		var metric *types.NetworkMetric
		p := deviceNetworkStatus.GetPortByLogicallabel(label)
		if p == nil {
			continue
		}
		for _, m := range networkMetrics.MetricList {
			if p.IfName == m.IfName {
				metric = &m
				break
			}
		}
		if metric == nil {
			continue
		}
		networkDetails := new(metrics.NetworkMetric)
		networkDetails.LocalName = metric.IfName
		networkDetails.IName = label
		networkDetails.Alias = p.Alias
		networkDetails.TxPkts = metric.TxPkts
		networkDetails.RxPkts = metric.RxPkts
		networkDetails.TxBytes = metric.TxBytes
		networkDetails.RxBytes = metric.RxBytes
		networkDetails.TxDrops = metric.TxDrops
		networkDetails.RxDrops = metric.RxDrops
		networkDetails.TxErrors = metric.TxErrors
		networkDetails.RxErrors = metric.RxErrors
		networkDetails.TxAclDrops = metric.TxAclDrops
		networkDetails.RxAclDrops = metric.RxAclDrops
		networkDetails.TxAclRateLimitDrops = metric.TxAclRateLimitDrops
		networkDetails.RxAclRateLimitDrops = metric.RxAclRateLimitDrops
		ReportDeviceMetric.Network = append(ReportDeviceMetric.Network,
			networkDetails)
	}

	lm, _ := ctx.subLogMetrics.Get("global")
	if lm != nil {
		logMetrics := lm.(types.LogMetrics)
		deviceLogMetric := new(metrics.LogMetric)
		deviceLogMetric.NumDeviceEventsSent = logMetrics.NumDeviceEventsSent
		deviceLogMetric.NumDeviceBundlesSent = logMetrics.NumDeviceBundlesSent
		deviceLogMetric.NumAppEventsSent = logMetrics.NumAppEventsSent
		deviceLogMetric.NumAppBundlesSent = logMetrics.NumAppBundlesSent
		deviceLogMetric.Num4XxResponses = logMetrics.Num4xxResponses
		pTime, _ := ptypes.TimestampProto(logMetrics.LastDeviceBundleSendTime)
		deviceLogMetric.LastDeviceBundleSendTime = pTime
		pTime, _ = ptypes.TimestampProto(logMetrics.LastAppBundleSendTime)
		deviceLogMetric.LastAppBundleSendTime = pTime
		deviceLogMetric.IsLogProcessingDeferred = logMetrics.IsLogProcessingDeferred
		deviceLogMetric.NumTimesDeferred = logMetrics.NumTimesDeferred
		pTime, _ = ptypes.TimestampProto(logMetrics.LastLogDeferTime)
		deviceLogMetric.LastLogDeferTime = pTime
		deviceLogMetric.TotalDeviceLogInput = logMetrics.TotalDeviceLogInput
		deviceLogMetric.TotalAppLogInput = logMetrics.TotalAppLogInput
		deviceLogMetric.NumDeviceEventErrors = logMetrics.NumDeviceEventErrors
		deviceLogMetric.NumAppEventErrors = logMetrics.NumAppEventErrors
		deviceLogMetric.NumDeviceBundleProtoBytesSent = logMetrics.NumDeviceBundleProtoBytesSent
		deviceLogMetric.NumAppBundleProtoBytesSent = logMetrics.NumAppBundleProtoBytesSent
		ReportDeviceMetric.Log = deviceLogMetric
	}
	log.Debugln("log metrics: ", ReportDeviceMetric.Log)

	// Collect zedcloud metrics from ourselves and other agents
	cms := zedcloud.GetCloudMetrics()
	if clientMetrics != nil {
		cms = zedcloud.Append(cms, clientMetrics)
	}
	if logmanagerMetrics != nil {
		cms = zedcloud.Append(cms, logmanagerMetrics)
	}
	if downloaderMetrics != nil {
		cms = zedcloud.Append(cms, downloaderMetrics)
	}
	for ifname, cm := range cms {
		metric := metrics.ZedcloudMetric{IfName: ifname,
			Failures:          cm.FailureCount,
			Success:           cm.SuccessCount,
			AuthVerifyFailure: cm.AuthFailCount,
		}
		if !cm.LastFailure.IsZero() {
			lf, _ := ptypes.TimestampProto(cm.LastFailure)
			metric.LastFailure = lf
		}
		if !cm.LastSuccess.IsZero() {
			ls, _ := ptypes.TimestampProto(cm.LastSuccess)
			metric.LastSuccess = ls
		}
		for url, um := range cm.URLCounters {
			log.Debugf("CloudMetrics[%s] url %s %v",
				ifname, url, um)
			urlMet := new(metrics.UrlcloudMetric)
			urlMet.Url = url
			urlMet.TryMsgCount = um.TryMsgCount
			urlMet.TryByteCount = um.TryByteCount
			urlMet.SentMsgCount = um.SentMsgCount
			urlMet.SentByteCount = um.SentByteCount
			urlMet.RecvMsgCount = um.RecvMsgCount
			urlMet.RecvByteCount = um.RecvByteCount
			metric.UrlMetrics = append(metric.UrlMetrics, urlMet)
		}
		ReportDeviceMetric.Zedcloud = append(ReportDeviceMetric.Zedcloud,
			&metric)
	}

	disks := findDisksPartitions()
	for _, d := range disks {
		size, _ := diskmetrics.PartitionSize(d)
		log.Debugf("Disk/partition %s size %d", d, size)
		size = RoundToMbytes(size)
		metric := metrics.DiskMetric{Disk: d, Total: size}
		stat, err := disk.IOCounters(d)
		if err == nil {
			metric.ReadBytes = RoundToMbytes(stat[d].ReadBytes)
			metric.WriteBytes = RoundToMbytes(stat[d].WriteBytes)
			metric.ReadCount = stat[d].ReadCount
			metric.WriteCount = stat[d].WriteCount
		}
		// XXX do we have a mountpath? Combine with paths below if same?
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}

	var persistUsage uint64
	for _, path := range reportDiskPaths {
		u, err := disk.Usage(path)
		if err != nil {
			// Happens e.g., if we don't have a /persist
			log.Errorf("disk.Usage: %s", err)
			continue
		}
		// We can not run diskmetrics.SizeFromDir("/persist") below in reportDirPaths, get the usage
		// data here for persistUsage
		if path == types.PersistDir {
			persistUsage = u.Used
		}
		log.Debugf("Path %s total %d used %d free %d",
			path, u.Total, u.Used, u.Free)
		metric := metrics.DiskMetric{MountPath: path,
			Total: RoundToMbytes(u.Total),
			Used:  RoundToMbytes(u.Used),
			Free:  RoundToMbytes(u.Free),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	log.Debugf("persistUsage %d, elapse sec %v", persistUsage, time.Since(startPubTime).Seconds())

	for _, path := range reportDirPaths {
		usage := diskmetrics.SizeFromDir(path)
		log.Debugf("Path %s usage %d", path, usage)
		metric := metrics.DiskMetric{MountPath: path,
			Used: RoundToMbytes(usage),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	log.Debugf("DirPaths in persist, elapse sec %v", time.Since(startPubTime).Seconds())

	// Determine how much we use in /persist and how much of it is
	// for the benefits of applications
	var persistAppUsage uint64
	for _, path := range appPersistPaths {
		persistAppUsage += diskmetrics.SizeFromDir(path)
	}
	log.Debugf("persistAppUsage %d, elapse sec %v", persistAppUsage, time.Since(startPubTime).Seconds())

	persistOverhead := persistUsage - persistAppUsage
	// Convert to MB
	runtimeStorageOverhead := types.RoundupToKB(types.RoundupToKB(persistOverhead))
	appRunTimeStorage := types.RoundupToKB(types.RoundupToKB(persistAppUsage))
	log.Debugf("runtimeStorageOverhead %d MB, appRunTimeStorage %d MB",
		runtimeStorageOverhead, appRunTimeStorage)
	ReportDeviceMetric.RuntimeStorageOverheadMB = runtimeStorageOverhead
	ReportDeviceMetric.AppRunTimeStorageMB = appRunTimeStorage

	// Walk all verified downloads and report their size (faked
	// as disks)
	verifierStatusMap := verifierGetAll(ctx)
	for _, st := range verifierStatusMap {
		vs := st.(types.VerifyImageStatus)
		log.Debugf("verifierStatusMap %s size %d",
			vs.Name, vs.Size)
		metric := metrics.DiskMetric{
			Disk:  vs.Name,
			Total: RoundToMbytes(uint64(vs.Size)),
			Used:  RoundToMbytes(uint64(vs.Size)),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	downloaderStatusMap := downloaderGetAll(ctx)
	for _, st := range downloaderStatusMap {
		ds := st.(types.DownloaderStatus)
		log.Debugf("downloaderStatusMap %s size %d",
			ds.Name, ds.Size)
		if _, found := verifierStatusMap[ds.Key()]; found {
			log.Debugf("Found verifierStatusMap for %s", ds.Key())
			continue
		}
		metric := metrics.DiskMetric{
			Disk:  ds.Name,
			Total: RoundToMbytes(uint64(ds.Size)),
			Used:  RoundToMbytes(uint64(ds.Size)),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}

	// Note that these are associated with the device and not with a
	// device name like ppp0 or wwan0
	lte := readLTEMetrics()
	for _, i := range lte {
		item := new(metrics.MetricItem)
		item.Key = i.Key
		item.Type = metrics.MetricItemType(i.Type)
		setMetricAnyValue(item, i.Value)
		ReportDeviceMetric.MetricItems = append(ReportDeviceMetric.MetricItems, item)
	}

	// Get device info using nil UUID
	dm := lookupDomainMetric(ctx, nilUUID.String())
	if dm != nil {
		log.Debugf("host CPU: %d, percent used %d",
			dm.CPUTotal, (100*dm.CPUTotal)/uint64(info.Uptime))
		ReportDeviceMetric.CpuMetric.Total = *proto.Uint64(dm.CPUTotal)

		ReportDeviceMetric.SystemServicesMemoryMB = new(metrics.MemoryMetric)
		ReportDeviceMetric.SystemServicesMemoryMB.UsedMem = dm.UsedMemory
		ReportDeviceMetric.SystemServicesMemoryMB.AvailMem = dm.AvailableMemory
		ReportDeviceMetric.SystemServicesMemoryMB.UsedPercentage = dm.UsedMemoryPercent
		ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage = (100.0 - (dm.UsedMemoryPercent))
		log.Debugf("host Memory: %v %v %v %v",
			ReportDeviceMetric.SystemServicesMemoryMB.UsedMem,
			ReportDeviceMetric.SystemServicesMemoryMB.AvailMem,
			ReportDeviceMetric.SystemServicesMemoryMB.UsedPercentage,
			ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage)
	}

	ReportMetrics.MetricContent = new(metrics.ZMetricMsg_Dm)
	if x, ok := ReportMetrics.GetMetricContent().(*metrics.ZMetricMsg_Dm); ok {
		x.Dm = ReportDeviceMetric
	}

	// Loop over AppInstanceStatus so we report before the instance has booted
	sub = ctx.getconfigCtx.subAppInstanceStatus
	items := sub.GetAll()
	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)

		ReportAppMetric := new(metrics.AppMetric)
		ReportAppMetric.Cpu = new(metrics.AppCpuMetric)
		ReportAppMetric.Memory = new(metrics.MemoryMetric)
		ReportAppMetric.AppName = aiStatus.DisplayName
		ReportAppMetric.AppID = aiStatus.Key()
		if !aiStatus.BootTime.IsZero() && aiStatus.Activated {
			elapsed := time.Since(aiStatus.BootTime)
			uptime, _ := ptypes.TimestampProto(
				time.Unix(0, elapsed.Nanoseconds()).UTC())
			ReportAppMetric.Cpu.UpTime = uptime
		}

		dm := lookupDomainMetric(ctx, aiStatus.Key())
		if dm != nil {
			log.Debugf("metrics for %s CPU %d, usedMem %v, availMem %v, availMemPercent %v",
				aiStatus.DomainName, dm.CPUTotal, dm.UsedMemory,
				dm.AvailableMemory, dm.UsedMemoryPercent)
			ReportAppMetric.Cpu.Total = *proto.Uint64(dm.CPUTotal)
			ReportAppMetric.Memory.UsedMem = dm.UsedMemory
			ReportAppMetric.Memory.AvailMem = dm.AvailableMemory
			ReportAppMetric.Memory.UsedPercentage = dm.UsedMemoryPercent
			availableMemoryPercent := 100.0 - dm.UsedMemoryPercent
			ReportAppMetric.Memory.AvailPercentage = availableMemoryPercent
		}

		appInterfaceList := aiStatus.GetAppInterfaceList()
		log.Debugf("ReportMetrics: domainName %s ifs %v",
			aiStatus.DomainName, appInterfaceList)
		// Use the network metrics from zedrouter subscription
		for _, ifName := range appInterfaceList {
			var metric *types.NetworkMetric
			for _, m := range networkMetrics.MetricList {
				if ifName == m.IfName {
					metric = &m
					break
				}
			}
			if metric == nil {
				continue
			}
			networkDetails := new(metrics.NetworkMetric)
			name := appIfnameToName(&aiStatus, metric.IfName)
			log.Debugf("app %s/%s localname %s name %s",
				aiStatus.Key(), aiStatus.DisplayName,
				metric.IfName, name)
			networkDetails.IName = name
			networkDetails.LocalName = metric.IfName
			// Counters not swapped on vif
			if strings.HasPrefix(ifName, "nbn") ||
				strings.HasPrefix(ifName, "nbu") ||
				strings.HasPrefix(ifName, "nbo") {
				networkDetails.TxPkts = metric.TxPkts
				networkDetails.RxPkts = metric.RxPkts
				networkDetails.TxBytes = metric.TxBytes
				networkDetails.RxBytes = metric.RxBytes
				networkDetails.TxDrops = metric.TxDrops
				networkDetails.RxDrops = metric.RxDrops
				networkDetails.TxErrors = metric.TxErrors
				networkDetails.RxErrors = metric.RxErrors
				networkDetails.TxAclDrops = metric.TxAclDrops
				networkDetails.RxAclDrops = metric.RxAclDrops
				networkDetails.TxAclRateLimitDrops = metric.TxAclRateLimitDrops
				networkDetails.RxAclRateLimitDrops = metric.RxAclRateLimitDrops
			} else {
				// Note that the packets received on bu* and bo* where sent
				// by the domU and vice versa, hence we swap here
				networkDetails.TxPkts = metric.RxPkts
				networkDetails.RxPkts = metric.TxPkts
				networkDetails.TxBytes = metric.RxBytes
				networkDetails.RxBytes = metric.TxBytes
				networkDetails.TxDrops = metric.RxDrops
				networkDetails.RxDrops = metric.TxDrops
				networkDetails.TxErrors = metric.RxErrors
				networkDetails.RxErrors = metric.TxErrors
				networkDetails.TxAclDrops = metric.RxAclDrops
				networkDetails.RxAclDrops = metric.TxAclDrops
				networkDetails.TxAclRateLimitDrops = metric.RxAclRateLimitDrops
				networkDetails.RxAclRateLimitDrops = metric.TxAclRateLimitDrops
			}
			ReportAppMetric.Network = append(ReportAppMetric.Network,
				networkDetails)
		}

		for _, ss := range aiStatus.StorageStatusList {
			appDiskDetails := new(metrics.AppDiskMetric)
			err := getDiskInfo(ss, appDiskDetails)
			if err != nil {
				log.Errorf("getDiskInfo(%s) failed %v",
					ss.ActiveFileLocation, err)
				continue
			}
			ReportAppMetric.Disk = append(ReportAppMetric.Disk,
				appDiskDetails)
		}

		acMetric := lookupAppContainerMetric(ctx, aiStatus.UUIDandVersion.UUID.String())
		// upload acMetric when it's been newly updated
		if acMetric != nil && acMetric.CollectTime.Sub(ctx.appContainerStatsTime) > 0 {
			for _, stats := range acMetric.StatsList { // go through each container
				appContainerMetric := new(metrics.AppContainerMetric)
				appContainerMetric.AppContainerName = stats.ContainerName
				appContainerMetric.Status = stats.Status
				appContainerMetric.PIDs = stats.Pids

				appContainerMetric.Cpu = new(metrics.AppCpuMetric)
				uptime, _ := ptypes.TimestampProto(time.Unix(0, stats.Uptime).UTC())
				appContainerMetric.Cpu.UpTime = uptime
				appContainerMetric.Cpu.Total = stats.CPUTotal
				appContainerMetric.Cpu.SystemTotal = stats.SystemCPUTotal

				appContainerMetric.Memory = new(metrics.MemoryMetric)
				appContainerMetric.Memory.UsedMem = stats.UsedMem
				appContainerMetric.Memory.AvailMem = stats.AvailMem

				appContainerMetric.Network = new(metrics.NetworkMetric)
				appContainerMetric.Network.TxBytes = stats.TxBytes
				appContainerMetric.Network.RxBytes = stats.RxBytes

				appContainerMetric.Disk = new(metrics.DiskMetric)
				appContainerMetric.Disk.ReadBytes = stats.ReadBytes
				appContainerMetric.Disk.WriteBytes = stats.WriteBytes

				ReportAppMetric.Container = append(ReportAppMetric.Container, appContainerMetric)
			}
			ctx.appContainerStatsTime = acMetric.CollectTime
		}

		ReportMetrics.Am = append(ReportMetrics.Am, ReportAppMetric)
	}

	createNetworkInstanceMetrics(ctx, ReportMetrics)

	log.Debugf("PublishMetricsToZedCloud sending %s", ReportMetrics)
	SendMetricsProtobuf(ReportMetrics, iteration)
	log.Debugf("publishMetrics: after send, total elapse sec %v", time.Since(startPubTime).Seconds())
}

func getDiskInfo(ss types.StorageStatus, appDiskDetails *metrics.AppDiskMetric) error {
	if ss.IsContainer {
		appDiskDetails.Disk = ss.ActiveFileLocation
		// XXX For container images, max size is coming zero
		// from the controller. So for now, we are setting up
		// total size equal to the used size.
		appDiskDetails.Provisioned = RoundToMbytes(ss.MaxDownSize)
		appDiskDetails.Used = RoundToMbytes(ss.MaxDownSize)
		appDiskDetails.DiskType = "CONTAINER"
	} else {
		imgInfo, err := diskmetrics.GetImgInfo(ss.ActiveFileLocation)
		if err != nil {
			return err
		}
		appDiskDetails.Disk = ss.ActiveFileLocation
		appDiskDetails.Provisioned = RoundToMbytes(imgInfo.VirtualSize)
		appDiskDetails.Used = RoundToMbytes(imgInfo.ActualSize)
		appDiskDetails.DiskType = imgInfo.Format
		appDiskDetails.Dirty = imgInfo.DirtyFlag
	}
	return nil
}

func RoundToMbytes(byteCount uint64) uint64 {
	const mbyte = 1024 * 1024

	return (byteCount + mbyte/2) / mbyte
}

//getDataSecAtRestInfo prepares status related to Data security at Rest
func getDataSecAtRestInfo(ctx *zedagentContext) *info.DataSecAtRest {
	subVaultStatus := ctx.subVaultStatus
	ReportDataSecAtRestInfo := new(info.DataSecAtRest)
	ReportDataSecAtRestInfo.VaultList = make([]*info.VaultInfo, 0)
	vaultList := subVaultStatus.GetAll()
	for _, vaultItem := range vaultList {
		vault := vaultItem.(types.VaultStatus)
		vaultInfo := new(info.VaultInfo)
		vaultInfo.Name = vault.Name
		vaultInfo.Status = vault.Status
		if !vault.ErrorTime.IsZero() {
			vaultInfo.VaultErr = encodeErrorInfo(vault.ErrorAndTime)
		}
		ReportDataSecAtRestInfo.VaultList = append(ReportDataSecAtRestInfo.VaultList, vaultInfo)
	}
	return ReportDataSecAtRestInfo
}

func createConfigItemStatus(
	status types.GlobalStatus) *info.ZInfoConfigItemStatus {

	cfgItemsPtr := new(info.ZInfoConfigItemStatus)

	// Copy ConfigItems
	cfgItemsPtr.ConfigItems = make(map[string]*info.ZInfoConfigItem)
	for key, statusCfgItem := range status.ConfigItems {
		if statusCfgItem.Err != nil {
			cfgItemsPtr.ConfigItems[key] = &info.ZInfoConfigItem{
				Value: statusCfgItem.Value,
				Error: statusCfgItem.Err.Error()}
		} else {
			cfgItemsPtr.ConfigItems[key] = &info.ZInfoConfigItem{
				Value: statusCfgItem.Value}
		}
	}

	// Copy Unknown Config Items
	cfgItemsPtr.UnknownConfigItems = make(map[string]*info.ZInfoConfigItem)
	for key, statusUnknownCfgItem := range status.UnknownConfigItems {
		cfgItemsPtr.UnknownConfigItems[key] = &info.ZInfoConfigItem{
			Value: statusUnknownCfgItem.Value,
			Error: statusUnknownCfgItem.Err.Error()}
	}
	return cfgItemsPtr
}

func createAppInstances(ctxPtr *zedagentContext,
	zinfoDevice *info.ZInfoDevice) {

	addAppInstanceFunc := func(key string, value interface{}) bool {
		ais := value.(types.AppInstanceStatus)
		zinfoAppInst := new(info.ZInfoAppInstance)
		zinfoAppInst.Uuid = ais.UUIDandVersion.UUID.String()
		zinfoAppInst.Name = ais.DisplayName
		zinfoAppInst.DomainName = ais.DomainName
		zinfoDevice.AppInstances = append(zinfoDevice.AppInstances,
			zinfoAppInst)
		return true
	}
	ctxPtr.getconfigCtx.subAppInstanceStatus.Iterate(
		addAppInstanceFunc)
}

// This function is called per change, hence needs to try over all management ports
func PublishDeviceInfoToZedCloud(ctx *zedagentContext) {
	aa := ctx.assignableAdapters
	iteration := ctx.iteration
	subBaseOsStatus := ctx.subBaseOsStatus

	var ReportInfo = &info.ZInfoMsg{}

	deviceType := new(info.ZInfoTypes)
	*deviceType = info.ZInfoTypes_ZiDevice
	ReportInfo.Ztype = *deviceType
	deviceUUID := zcdevUUID.String()
	ReportInfo.DevId = *proto.String(deviceUUID)
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()
	log.Infof("PublishDeviceInfoToZedCloud uuid %s", deviceUUID)

	ReportDeviceInfo := new(info.ZInfoDevice)

	var machineArch string
	machineCmd := exec.Command("uname", "-m")
	stdout, err := machineCmd.Output()
	if err != nil {
		log.Errorf("uname -m failed %s", err)
	} else {
		machineArch = string(stdout)
		ReportDeviceInfo.MachineArch = *proto.String(strings.TrimSpace(machineArch))
	}

	cpuCmd := exec.Command("uname", "-p")
	stdout, err = cpuCmd.Output()
	if err != nil {
		log.Errorf("uname -p failed %s", err)
	} else {
		cpuArch := string(stdout)
		ReportDeviceInfo.CpuArch = *proto.String(strings.TrimSpace(cpuArch))
	}

	platformCmd := exec.Command("uname", "-i")
	stdout, err = platformCmd.Output()
	if err != nil {
		log.Errorf("uname -i failed %s", err)
	} else {
		platform := string(stdout)
		ReportDeviceInfo.Platform = *proto.String(strings.TrimSpace(platform))
	}

	sub := ctx.getconfigCtx.subHostMemory
	m, _ := sub.Get("global")
	if m != nil {
		metric := m.(types.HostMemory)
		ReportDeviceInfo.Ncpu = *proto.Uint32(metric.Ncpus)
		ReportDeviceInfo.Memory = *proto.Uint64(metric.TotalMemoryMB)
	}
	// Find all disks and partitions
	disks := findDisksPartitions()
	ReportDeviceInfo.Storage = *proto.Uint64(0)
	for _, disk := range disks {
		size, _ := diskmetrics.PartitionSize(disk)
		log.Debugf("Disk/partition %s size %d", disk, size)
		size = RoundToMbytes(size)
		is := info.ZInfoStorage{Device: disk, Total: size}
		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList,
			&is)
		// XXX should we report whether it is a disk or a partition?
	}
	for _, path := range reportDiskPaths {
		u, err := disk.Usage(path)
		if err != nil {
			// Happens e.g., if we don't have a /persist
			log.Errorf("disk.Usage: %s", err)
			continue
		}
		log.Debugf("Path %s total %d used %d free %d",
			path, u.Total, u.Used, u.Free)
		size := RoundToMbytes(u.Total)
		is := info.ZInfoStorage{MountPath: path, Total: size}
		// We know this is where we store images and keep
		// domU virtual disks.
		if path == types.PersistDir {
			is.StorageLocation = true
			ReportDeviceInfo.Storage += *proto.Uint64(size)
		}
		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList,
			&is)
	}

	ReportDeviceManufacturerInfo := new(info.ZInfoManufacturer)
	if strings.Contains(machineArch, "x86") {
		productManufacturer, productName, productVersion, productSerial, productUuid := hardware.GetDeviceManufacturerInfo()
		ReportDeviceManufacturerInfo.Manufacturer = *proto.String(strings.TrimSpace(productManufacturer))
		ReportDeviceManufacturerInfo.ProductName = *proto.String(strings.TrimSpace(productName))
		ReportDeviceManufacturerInfo.Version = *proto.String(strings.TrimSpace(productVersion))
		ReportDeviceManufacturerInfo.SerialNumber = *proto.String(strings.TrimSpace(productSerial))
		ReportDeviceManufacturerInfo.UUID = *proto.String(strings.TrimSpace(productUuid))

		biosVendor, biosVersion, biosReleaseDate := hardware.GetDeviceBios()
		ReportDeviceManufacturerInfo.BiosVendor = *proto.String(strings.TrimSpace(biosVendor))
		ReportDeviceManufacturerInfo.BiosVersion = *proto.String(strings.TrimSpace(biosVersion))
		ReportDeviceManufacturerInfo.BiosReleaseDate = *proto.String(strings.TrimSpace(biosReleaseDate))
	}
	compatible := hardware.GetCompatible()
	ReportDeviceManufacturerInfo.Compatible = *proto.String(compatible)
	ReportDeviceInfo.Minfo = ReportDeviceManufacturerInfo

	// Report BaseOs Status for the two partitions
	getBaseOsStatus := func(partLabel string) *types.BaseOsStatus {
		// Look for a matching IMGA/IMGB in baseOsStatus
		items := subBaseOsStatus.GetAll()
		for _, st := range items {
			bos := st.(types.BaseOsStatus)
			if bos.PartitionLabel == partLabel {
				return &bos
			}
		}
		return nil
	}
	getSwInfo := func(partLabel string) *info.ZInfoDevSW {
		swInfo := new(info.ZInfoDevSW)
		if bos := getBaseOsStatus(partLabel); bos != nil {
			// Get current state/version which is different than
			// what is on disk
			swInfo.Activated = bos.Activated
			swInfo.PartitionLabel = bos.PartitionLabel
			swInfo.PartitionDevice = bos.PartitionDevice
			swInfo.PartitionState = bos.PartitionState
			swInfo.Status = bos.State.ZSwState()
			swInfo.ShortVersion = bos.BaseOsVersion
			swInfo.LongVersion = "" // XXX
			if len(bos.StorageStatusList) > 0 {
				// Assume one - pick first StorageStatus
				swInfo.DownloadProgress = uint32(bos.StorageStatusList[0].Progress)
			}
			if !bos.ErrorTime.IsZero() {
				log.Debugf("reportMetrics sending error time %v error %v for %s",
					bos.ErrorTime, bos.Error,
					bos.BaseOsVersion)
				swInfo.SwErr = encodeErrorInfo(bos.ErrorAndTime)
			}
			if swInfo.ShortVersion == "" {
				swInfo.Status = info.ZSwState_INITIAL
				swInfo.DownloadProgress = 0
			}
		} else {
			partStatus := getZbootPartitionStatus(ctx, partLabel)
			swInfo.PartitionLabel = partLabel
			if partStatus != nil {
				swInfo.Activated = partStatus.CurrentPartition
				swInfo.PartitionDevice = partStatus.PartitionDevname
				swInfo.PartitionState = partStatus.PartitionState
				swInfo.ShortVersion = partStatus.ShortVersion
				swInfo.LongVersion = partStatus.LongVersion
			}
			if swInfo.ShortVersion != "" {
				swInfo.Status = info.ZSwState_INSTALLED
				swInfo.DownloadProgress = 100
			} else {
				swInfo.Status = info.ZSwState_INITIAL
				swInfo.DownloadProgress = 0
			}
		}
		addUserSwInfo(ctx, swInfo)
		return swInfo
	}

	ReportDeviceInfo.SwList = make([]*info.ZInfoDevSW, 2)
	ReportDeviceInfo.SwList[0] = getSwInfo(getZbootCurrentPartition(ctx))
	ReportDeviceInfo.SwList[1] = getSwInfo(getZbootOtherPartition(ctx))
	// Report any other BaseOsStatus which might have errors
	items := subBaseOsStatus.GetAll()
	for _, st := range items {
		bos := st.(types.BaseOsStatus)
		if bos.PartitionLabel != "" {
			// Already reported above
			continue
		}
		log.Debugf("reportMetrics sending unattached bos for %s",
			bos.BaseOsVersion)
		swInfo := new(info.ZInfoDevSW)
		swInfo.Status = bos.State.ZSwState()
		swInfo.ShortVersion = bos.BaseOsVersion
		swInfo.LongVersion = "" // XXX
		if len(bos.StorageStatusList) > 0 {
			// Assume one - pick first StorageStatus
			swInfo.DownloadProgress = uint32(bos.StorageStatusList[0].Progress)
		}
		if !bos.ErrorTime.IsZero() {
			log.Debugf("reportMetrics sending error time %v error %v for %s",
				bos.ErrorTime, bos.Error, bos.BaseOsVersion)
			swInfo.SwErr = encodeErrorInfo(bos.ErrorAndTime)
		}
		addUserSwInfo(ctx, swInfo)
		ReportDeviceInfo.SwList = append(ReportDeviceInfo.SwList,
			swInfo)
	}

	// Read interface name from library and match it with port name from
	// global status. Only report the ports in DeviceNetworkStatus
	interfaces, _ := psutilnet.Interfaces()
	labelList := types.ReportLogicallabels(*deviceNetworkStatus)
	for _, label := range labelList {
		p := deviceNetworkStatus.GetPortByLogicallabel(label)
		if p == nil {
			continue
		}
		for _, interfaceDetail := range interfaces {
			if p.IfName != interfaceDetail.Name {
				continue
			}
			ReportDeviceNetworkInfo := getNetInfo(interfaceDetail, true)
			// XXX rename DevName to Logicallabel in proto file
			ReportDeviceNetworkInfo.DevName = *proto.String(label)
			ReportDeviceNetworkInfo.Alias = *proto.String(p.Alias)
			ReportDeviceInfo.Network = append(ReportDeviceInfo.Network,
				ReportDeviceNetworkInfo)
		}
	}
	// Fill in global ZInfoDNS dns from /etc/resolv.conf
	// Note that "domain" is returned in search, hence DNSdomain is
	// not filled in.
	dc := netclone.DnsReadConfig("/etc/resolv.conf")
	log.Debugf("resolv.conf servers %v", dc.Servers)
	log.Debugf("resolv.conf search %v", dc.Search)

	ReportDeviceInfo.Dns = new(info.ZInfoDNS)
	ReportDeviceInfo.Dns.DNSservers = dc.Servers
	ReportDeviceInfo.Dns.DNSsearch = dc.Search

	// Report AssignableAdapters.
	// Domainmgr excludes adapters which do not currently exist in
	// what it publishes.
	// We also mark current management ports as such.
	var seenBundles []string
	for _, ib := range aa.IoBundleList {
		// Report each group once
		seen := false
		for _, s := range seenBundles {
			if s == ib.AssignmentGroup {
				seen = true
				break
			}
		}
		if seen && ib.AssignmentGroup != "" {
			continue
		}
		seenBundles = append(seenBundles, ib.AssignmentGroup)
		reportAA := new(info.ZioBundle)
		reportAA.Type = evecommon.PhyIoType(ib.Type)
		reportAA.Name = ib.AssignmentGroup
		// XXX - Cast is needed because PhyIoMemberUsage was replicated in info
		//  When this is fixed, we can remove this case.
		reportAA.Usage = evecommon.PhyIoMemberUsage(ib.Usage)
		list := aa.LookupIoBundleGroup(ib.AssignmentGroup)
		if len(list) == 0 {
			if ib.AssignmentGroup != "" {
				log.Infof("Nothing to report for %d %s",
					ib.Type, ib.AssignmentGroup)
				continue
			}
			// Singleton
			list = append(list, &ib)
		}
		for _, b := range list {
			if b == nil {
				continue
			}
			reportAA.Members = append(reportAA.Members,
				b.Phylabel)
			if b.MacAddr != "" {
				reportMac := new(info.IoAddresses)
				reportMac.MacAddress = b.MacAddr
				reportAA.IoAddressList = append(reportAA.IoAddressList,
					reportMac)
			}
		}
		if ib.IsPort {
			reportAA.UsedByBaseOS = true
		} else if ib.UsedByUUID != nilUUID {
			reportAA.UsedByAppUUID = ib.UsedByUUID.String()
		}
		log.Debugf("AssignableAdapters for %s macs %v",
			reportAA.Name, reportAA.IoAddressList)
		ReportDeviceInfo.AssignableAdapters = append(ReportDeviceInfo.AssignableAdapters,
			reportAA)
	}

	hinfo, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s", err)
	}
	log.Debugf("uptime %d = %d days",
		hinfo.Uptime, hinfo.Uptime/(3600*24))
	log.Debugf("Booted at %v", time.Unix(int64(hinfo.BootTime), 0).UTC())

	bootTime, _ := ptypes.TimestampProto(
		time.Unix(int64(hinfo.BootTime), 0).UTC())
	ReportDeviceInfo.BootTime = bootTime
	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("HostName failed: %s", err)
	} else {
		ReportDeviceInfo.HostName = hostname
	}

	// Note that these are associated with the device and not with a
	// device name like ppp0 or wwan0
	lte := readLTEInfo()
	lteNets := readLTENetworks()
	if lteNets != nil {
		lte = append(lte, lteNets...)
	}
	for _, i := range lte {
		item := new(info.DeprecatedMetricItem)
		item.Key = i.Key
		item.Type = info.DepMetricItemType(i.Type)
		// setDeprecatedMetricAnyValue(item, i.Value)
		ReportDeviceInfo.MetricItems = append(ReportDeviceInfo.MetricItems, item)
	}

	ReportDeviceInfo.LastRebootReason = ctx.rebootReason
	ReportDeviceInfo.LastRebootStack = ctx.rebootStack
	if !ctx.rebootTime.IsZero() {
		rebootTime, _ := ptypes.TimestampProto(ctx.rebootTime)
		ReportDeviceInfo.LastRebootTime = rebootTime
	}

	ReportDeviceInfo.SystemAdapter = encodeSystemAdapterInfo(ctx)

	ReportDeviceInfo.RestartCounter = ctx.restartCounter
	ReportDeviceInfo.RebootConfigCounter = ctx.rebootConfigCounter

	//Operational information about TPM presence/absence/usage.
	ReportDeviceInfo.HSMStatus = tpmmgr.FetchTpmSwStatus()
	ReportDeviceInfo.HSMInfo, _ = tpmmgr.FetchTpmHwInfo()

	//Operational information about Data Security At Rest
	ReportDataSecAtRestInfo := getDataSecAtRestInfo(ctx)

	//This will be removed after new fields propagate to Controller.
	ReportDataSecAtRestInfo.Status, ReportDataSecAtRestInfo.Info =
		vaultmgr.GetOperInfo()
	ReportDeviceInfo.DataSecAtRestInfo = ReportDataSecAtRestInfo

	ReportInfo.InfoContent = new(info.ZInfoMsg_Dinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Dinfo); ok {
		x.Dinfo = ReportDeviceInfo
	}

	// Add ConfigItems to the DeviceInfo
	ReportDeviceInfo.ConfigItemStatus = createConfigItemStatus(ctx.globalStatus)

	// Add AppInstances to the DeviceInfo. We send a list of all AppInstances
	// currently on the device - even if the corresponding AppInstanceConfig
	// is deleted.
	createAppInstances(ctx, ReportDeviceInfo)

	log.Debugf("PublishDeviceInfoToZedCloud sending %v", ReportInfo)
	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishDeviceInfoToZedCloud proto marshaling error: ", err)
	}

	statusUrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")
	zedcloud.RemoveDeferred(deviceUUID)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishDeviceInfoToZedCloud failed: %s", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(deviceUUID, buf, size, statusUrl,
			zedcloudCtx, true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}

// Convert the implementation details to the user-friendly userStatus and subStatus*
func addUserSwInfo(ctx *zedagentContext, swInfo *info.ZInfoDevSW) {
	switch swInfo.Status {
	case info.ZSwState_INITIAL:
		// If Unused and partitionLabel is set them it
		// is the uninitialized IMGB partition which we don't report
		if swInfo.PartitionState == "unused" &&
			swInfo.PartitionLabel != "" {

			swInfo.UserStatus = info.BaseOsStatus_NONE
		} else if swInfo.ShortVersion == "" {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		} else {
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_INITIALIZING
			swInfo.SubStatusStr = "Initializing update"
		}
	case info.ZSwState_DOWNLOAD_STARTED:
		swInfo.UserStatus = info.BaseOsStatus_DOWNLOADING
		swInfo.SubStatus = info.BaseOsSubStatus_DOWNLOAD_INPROGRESS
		swInfo.SubStatusProgress = swInfo.DownloadProgress
		swInfo.SubStatusStr = fmt.Sprintf("Download %d%% done",
			swInfo.SubStatusProgress)
	case info.ZSwState_DOWNLOADED:
		if swInfo.Activated {
			swInfo.UserStatus = info.BaseOsStatus_DOWNLOADING
			swInfo.SubStatus = info.BaseOsSubStatus_DOWNLOAD_INPROGRESS
			swInfo.SubStatusProgress = 100
			swInfo.SubStatusStr = "Download 100% done"
		} else {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	case info.ZSwState_DELIVERED:
		if swInfo.Activated {
			swInfo.UserStatus = info.BaseOsStatus_DOWNLOAD_DONE
			swInfo.SubStatusStr = "Downloaded and verified"
		} else {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	case info.ZSwState_INSTALLED:
		switch swInfo.PartitionState {
		case "active":
			if swInfo.Activated {
				swInfo.UserStatus = info.BaseOsStatus_UPDATED
			} else {
				swInfo.UserStatus = info.BaseOsStatus_FALLBACK
			}
		case "updating":
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_REBOOTING
			// XXX progress based on time left??
			swInfo.SubStatusStr = "About to reboot"
		case "inprogress":
			if swInfo.Activated {
				swInfo.UserStatus = info.BaseOsStatus_UPDATING
				swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_TESTING
				swInfo.SubStatusProgress = uint32(ctx.remainingTestTime / time.Second)
				swInfo.SubStatusStr = fmt.Sprintf("Testing for %d more seconds",
					swInfo.SubStatusProgress)
			} else {
				swInfo.UserStatus = info.BaseOsStatus_FAILED
			}

		case "unused":
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	default:
		// The other states are use for app instances not for baseos
		swInfo.UserStatus = info.BaseOsStatus_NONE
	}
	if swInfo.SwErr != nil && swInfo.SwErr.Description != "" {
		swInfo.UserStatus = info.BaseOsStatus_FAILED
	}
}

func setMetricAnyValue(item *metrics.MetricItem, val interface{}) {
	switch t := val.(type) {
	case uint32:
		u := val.(uint32)
		item.MetricItemValue = new(metrics.MetricItem_Uint32Value)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_Uint32Value); ok {
			x.Uint32Value = u
		}
	case uint64:
		u := val.(uint64)
		item.MetricItemValue = new(metrics.MetricItem_Uint64Value)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_Uint64Value); ok {
			x.Uint64Value = u
		}
	case bool:
		b := val.(bool)
		item.MetricItemValue = new(metrics.MetricItem_BoolValue)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_BoolValue); ok {
			x.BoolValue = b
		}
	case float32:
		f := val.(float32)
		item.MetricItemValue = new(metrics.MetricItem_FloatValue)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_FloatValue); ok {
			x.FloatValue = f
		}

	case string:
		s := val.(string)
		item.MetricItemValue = new(metrics.MetricItem_StringValue)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_StringValue); ok {
			x.StringValue = s
		}

	default:
		log.Errorf("setMetricAnyValue unknown %T", t)
	}
}

var nilIPInfo = ipinfo.IPInfo{}

func getNetInfo(interfaceDetail psutilnet.InterfaceStat,
	getAddrs bool) *info.ZInfoNetwork {

	networkInfo := new(info.ZInfoNetwork)
	networkInfo.LocalName = *proto.String(interfaceDetail.Name)
	if getAddrs {
		networkInfo.IPAddrs = make([]string, len(interfaceDetail.Addrs))
		for index, ip := range interfaceDetail.Addrs {
			networkInfo.IPAddrs[index] = *proto.String(ip.Addr)
		}
		networkInfo.MacAddr = *proto.String(interfaceDetail.HardwareAddr)
		// In case caller doesn't override
		networkInfo.DevName = *proto.String(networkInfo.LocalName)

		// Default routers from kernel whether or not we are using DHCP
		drs := getDefaultRouters(interfaceDetail.Name)
		networkInfo.DefaultRouters = make([]string, len(drs))
		for index, dr := range drs {
			log.Debugf("got dr: %v", dr)
			networkInfo.DefaultRouters[index] = *proto.String(dr)
		}
	}
	for _, fl := range interfaceDetail.Flags {
		if fl == "up" {
			networkInfo.Up = true
			break
		}
	}

	port := types.GetPort(*deviceNetworkStatus, interfaceDetail.Name)
	if port != nil {
		networkInfo.Uplink = port.IsMgmt
		// fill in ZInfoDNS
		networkInfo.Dns = new(info.ZInfoDNS)
		networkInfo.Dns.DNSdomain = port.NetworkXConfig.DomainName
		for _, server := range port.NetworkXConfig.DnsServers {
			networkInfo.Dns.DNSservers = append(networkInfo.Dns.DNSservers,
				server.String())
		}

		// XXX we potentially have geoloc information for each IP
		// address.
		// For now fill in using the first IP address which has location
		// info.
		for _, ai := range port.AddrInfoList {
			if ai.Geo == nilIPInfo {
				continue
			}
			geo := new(info.GeoLoc)
			geo.UnderlayIP = *proto.String(ai.Geo.IP)
			geo.Hostname = *proto.String(ai.Geo.Hostname)
			geo.City = *proto.String(ai.Geo.City)
			geo.Country = *proto.String(ai.Geo.Country)
			geo.Loc = *proto.String(ai.Geo.Loc)
			geo.Org = *proto.String(ai.Geo.Org)
			geo.Postal = *proto.String(ai.Geo.Postal)
			networkInfo.Location = geo
			break
		}
		// Any error or test result?
		networkInfo.NetworkErr = encodeTestResults(port.TestResults)
		networkInfo.Proxy = encodeProxyStatus(&port.ProxyConfig)
	}
	return networkInfo
}

func encodeProxyStatus(proxyConfig *types.ProxyConfig) *info.ProxyStatus {
	status := new(info.ProxyStatus)
	status.Proxies = make([]*info.ProxyEntry, len(proxyConfig.Proxies))
	for i, pe := range proxyConfig.Proxies {
		pep := new(info.ProxyEntry)
		pep.Type = uint32(pe.Type)
		pep.Server = pe.Server
		pep.Port = pe.Port
		status.Proxies[i] = pep
	}
	status.Exceptions = proxyConfig.Exceptions
	status.Pacfile = proxyConfig.Pacfile
	status.NetworkProxyEnable = proxyConfig.NetworkProxyEnable
	status.NetworkProxyURL = proxyConfig.NetworkProxyURL
	status.WpadURL = proxyConfig.WpadURL
	// XXX add? status.ProxyCertPEM = proxyConfig.ProxyCertPEM
	log.Debugf("encodeProxyStatus: %+v", status)
	return status
}

func encodeSystemAdapterInfo(ctx *zedagentContext) *info.SystemAdapterInfo {
	dpcl := ctx.devicePortConfigList
	sainfo := new(info.SystemAdapterInfo)
	sainfo.CurrentIndex = uint32(dpcl.CurrentIndex)
	sainfo.Status = make([]*info.DevicePortStatus, len(dpcl.PortConfigList))
	for i, dpc := range dpcl.PortConfigList {
		dps := new(info.DevicePortStatus)
		dps.Version = uint32(dpc.Version)
		dps.Key = dpc.Key
		ts, _ := ptypes.TimestampProto(dpc.TimePriority)
		dps.TimePriority = ts
		if !dpc.LastFailed.IsZero() {
			ts, _ := ptypes.TimestampProto(dpc.LastFailed)
			dps.LastFailed = ts
		}
		if !dpc.LastSucceeded.IsZero() {
			ts, _ := ptypes.TimestampProto(dpc.LastSucceeded)
			dps.LastSucceeded = ts
		}
		dps.LastError = dpc.LastError

		dps.Ports = make([]*info.DevicePort, len(dpc.Ports))
		for j, p := range dpc.Ports {
			dps.Ports[j] = encodeNetworkPortConfig(ctx, &p)
		}
		sainfo.Status[i] = dps
	}
	log.Debugf("encodeSystemAdapterInfo: %+v", sainfo)
	return sainfo
}

func encodeNetworkPortConfig(ctx *zedagentContext,
	npc *types.NetworkPortConfig) *info.DevicePort {
	aa := ctx.assignableAdapters

	dp := new(info.DevicePort)
	dp.Ifname = npc.IfName
	// XXX rename the protobuf field Name to Logicallabel and add Phylabel?
	dp.Name = npc.Logicallabel
	// XXX Add Alias in proto file?
	// dp.Alias = npc.Alias

	ibPtr := aa.LookupIoBundlePhylabel(npc.Phylabel)
	if ibPtr != nil {
		dp.Usage = evecommon.PhyIoMemberUsage(ibPtr.Usage)
	}

	dp.IsMgmt = npc.IsMgmt
	dp.Free = npc.Free
	// DhcpConfig
	dp.DhcpType = uint32(npc.Dhcp)
	dp.Subnet = npc.AddrSubnet

	dp.DefaultRouters = make([]string, 0)
	dp.DefaultRouters = append(dp.DefaultRouters, npc.Gateway.String())

	dp.NtpServer = npc.NtpServer.String()

	dp.Dns = new(info.ZInfoDNS)
	dp.Dns.DNSdomain = npc.DomainName
	dp.Dns.DNSservers = make([]string, 0)
	for _, d := range npc.DnsServers {
		dp.Dns.DNSservers = append(dp.Dns.DNSservers, d.String())
	}
	// XXX Not in definition. Remove?
	// XXX  string dhcpRangeLow = 17;
	// XXX  string dhcpRangeHigh = 18;

	dp.Proxy = encodeProxyStatus(&npc.ProxyConfig)

	dp.Err = encodeTestResults(npc.TestResults)

	var nilUUID uuid.UUID
	if npc.NetworkUUID != nilUUID {
		dp.NetworkUUID = npc.NetworkUUID.String()
	}
	return dp
}

// This function is called per change, hence needs to try over all management ports
// When aiStatus is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishAppInfoToZedCloud(ctx *zedagentContext, uuid string,
	aiStatus *types.AppInstanceStatus,
	aa *types.AssignableAdapters, iteration int) {
	log.Infof("PublishAppInfoToZedCloud uuid %s", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	appType := new(info.ZInfoTypes)
	*appType = info.ZInfoTypes_ZiApp
	ReportInfo.Ztype = *appType
	ReportInfo.DevId = *proto.String(zcdevUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportAppInfo := new(info.ZInfoApp)

	ReportAppInfo.AppID = uuid
	ReportAppInfo.SystemApp = false
	ReportAppInfo.State = info.ZSwState_HALTED
	if aiStatus != nil {
		ReportAppInfo.AppName = aiStatus.DisplayName
		ReportAppInfo.State = aiStatus.State.ZSwState()

		if !aiStatus.ErrorTime.IsZero() {
			errInfo := encodeErrorInfo(
				aiStatus.ErrorAndTimeWithSource.ErrorAndTime())
			ReportAppInfo.AppErr = append(ReportAppInfo.AppErr,
				errInfo)
		}

		if len(aiStatus.StorageStatusList) == 0 {
			log.Infof("storage status detail is empty so ignoring")
		} else {
			ReportAppInfo.SoftwareList = make([]*info.ZInfoSW, len(aiStatus.StorageStatusList))
			for idx, ss := range aiStatus.StorageStatusList {
				ReportSoftwareInfo := new(info.ZInfoSW)
				ReportSoftwareInfo.SwVersion = aiStatus.UUIDandVersion.Version
				ReportSoftwareInfo.ImageName = ss.Name
				ReportSoftwareInfo.SwHash = ss.ImageSha256
				ReportSoftwareInfo.State = ss.State.ZSwState()
				ReportSoftwareInfo.DownloadProgress = uint32(ss.Progress)

				ReportSoftwareInfo.Target = ss.Target
				ReportSoftwareInfo.Vdev = ss.Vdev

				ReportAppInfo.SoftwareList[idx] = ReportSoftwareInfo
			}
		}
		if aiStatus.BootTime.IsZero() {
			// If never booted
			log.Infoln("BootTime is empty")
		} else {
			bootTime, _ := ptypes.TimestampProto(aiStatus.BootTime)
			ReportAppInfo.BootTime = bootTime
		}

		for _, ia := range aiStatus.IoAdapterList {
			reportAA := new(info.ZioBundle)
			reportAA.Type = evecommon.PhyIoType(ia.Type)
			reportAA.Name = ia.Name
			reportAA.UsedByAppUUID = aiStatus.Key()
			list := aa.LookupIoBundleAny(ia.Name)
			for _, ib := range list {
				if ib == nil {
					continue
				}
				reportAA.Members = append(reportAA.Members, ib.Phylabel)
				if ib.MacAddr != "" {
					reportMac := new(info.IoAddresses)
					reportMac.MacAddress = ib.MacAddr
					reportAA.IoAddressList = append(reportAA.IoAddressList,
						reportMac)
				}
				log.Debugf("AssignableAdapters for %s macs %v",
					reportAA.Name, reportAA.IoAddressList)
			}
			ReportAppInfo.AssignedAdapters = append(ReportAppInfo.AssignedAdapters,
				reportAA)
		}
		// Get vifs assigned to the application
		// Mostly reporting the UP status
		// We extract the appIP from the dnsmasq assignment
		interfaces, _ := psutilnet.Interfaces()
		ifNames := (*aiStatus).GetAppInterfaceList()
		log.Debugf("ReportAppInfo: domainName %s ifs %v",
			aiStatus.DomainName, ifNames)
		for _, ifname := range ifNames {
			for _, interfaceDetail := range interfaces {
				if ifname != interfaceDetail.Name {
					continue
				}
				networkInfo := getNetInfo(interfaceDetail, false)
				ip, allocated, macAddr := getAppIP(ctx, aiStatus,
					ifname)
				networkInfo.IPAddrs = make([]string, 1)
				networkInfo.IPAddrs[0] = *proto.String(ip)
				networkInfo.MacAddr = *proto.String(macAddr)
				networkInfo.Up = allocated
				name := appIfnameToName(aiStatus, ifname)
				log.Debugf("app %s/%s localName %s devName %s",
					aiStatus.Key(), aiStatus.DisplayName,
					ifname, name)
				networkInfo.DevName = *proto.String(name)
				ReportAppInfo.Network = append(ReportAppInfo.Network,
					networkInfo)
			}
		}
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	log.Infof("PublishAppInfoToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishAppInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")

	zedcloud.RemoveDeferred(uuid)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishAppInfoToZedCloud failed: %s", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(uuid, buf, size, statusUrl, zedcloudCtx,
			true)
	} else {
		writeSentAppInfoProtoMessage(data)
	}
}

// PublishContentInfoToZedCloud is called per change, hence needs to try over all management ports
// When content tree Status is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishContentInfoToZedCloud(ctx *zedagentContext, uuid string,
	ctStatus *types.ContentTreeStatus, iteration int) {

	log.Infof("PublishContentInfoToZedCloud uuid %s", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	contentType := new(info.ZInfoTypes)
	*contentType = info.ZInfoTypes_ZiContentTree
	ReportInfo.Ztype = *contentType
	ReportInfo.DevId = *proto.String(zcdevUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportContentInfo := new(info.ZInfoContentTree)

	ReportContentInfo.Uuid = uuid
	ReportContentInfo.State = info.ZSwState_HALTED
	if ctStatus != nil {
		ReportContentInfo.DisplayName = ctStatus.DisplayName
		ReportContentInfo.State = ctStatus.State.ZSwState()

		if !ctStatus.ErrorTime.IsZero() {
			errInfo := encodeErrorInfo(
				ctStatus.ErrorAndTimeWithSource.ErrorAndTime())
			ReportContentInfo.Err = errInfo
		}

		ReportContentInfo.Sha256 = ctStatus.ContentSha256
		ReportContentInfo.ProgressPercentage = uint32(ctStatus.Progress)
		ReportContentInfo.GenerationCount = ctStatus.GenerationCounter
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Cinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Cinfo); ok {
		x.Cinfo = ReportContentInfo
	}

	log.Infof("PublishContentInfoToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishContentInfoToZedCloud proto marshaling error: ", err)
	}
	statusURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")

	zedcloud.RemoveDeferred(uuid)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusURL, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishContentInfoToZedCloud failed: %s", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(uuid, buf, size, statusURL, zedcloudCtx,
			true)
	}
}

func appIfnameToName(aiStatus *types.AppInstanceStatus, vifname string) string {
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.VifUsed == vifname {
			return ulStatus.Name
		}
	}
	for _, olStatus := range aiStatus.OverlayNetworks {
		if olStatus.VifUsed == vifname {
			return olStatus.Name
		}
	}
	return ""
}

// This function is called per change, hence needs to try over all management ports
// For each port we try different source IPs until we find a working one.
// For the HTTP errors indicating the object is gone we ignore the error
// so the caller does not defer and retry
func SendProtobuf(url string, buf *bytes.Buffer, size int64,
	iteration int) error {

	const bailOnHTTPErr = true // For 4xx and 5xx HTTP errors we don't try other interfaces
	resp, _, _, err := zedcloud.SendOnAllIntf(&zedcloudCtx, url,
		size, buf, iteration, bailOnHTTPErr)
	if resp != nil {
		switch resp.StatusCode {
		// XXX Some controller gives a generic 400 which should be fixed
		case http.StatusBadRequest:
			log.Warnf("XXX SendProtoBuf: %s silently ignore code %d %s",
				url, resp.StatusCode, http.StatusText(resp.StatusCode))
			return nil

		case http.StatusNotFound, http.StatusGone:
			// Assume the resource is gone in the controller

			log.Infof("SendProtoBuf: %s silently ignore code %d %s",
				url, resp.StatusCode, http.StatusText(resp.StatusCode))
			return nil
		}
	}
	return err
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func SendMetricsProtobuf(ReportMetrics *metrics.ZMetricMsg,
	iteration int) {
	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(ReportMetrics))
	metricsUrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "metrics")
	const bailOnHTTPErr = false
	_, _, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx, metricsUrl,
		size, buf, iteration, bailOnHTTPErr)
	if err != nil {
		// Hopefully next timeout will be more successful
		if rtf == types.SenderStatusRemTempFail {
			log.Errorf("SendMetricsProtobuf remoteTemporaryFailure: %s",
				err)
		} else {
			log.Errorf("SendMetricsProtobuf failed: %s", err)
		}
		return
	} else {
		writeSentMetricsProtoMessage(data)
	}
}

// Return an array of names like "sda", "sdb1"
func findDisksPartitions() []string {
	out, err := exec.Command("lsblk", "-nlo", "NAME").Output()
	if err != nil {
		log.Errorf("lsblk -nlo NAME failed %s", err)
		return nil
	}
	res := strings.Split(string(out), "\n")
	// Remove blank/empty string after last CR
	res = res[:len(res)-1]
	return res
}

func getDefaultRouters(ifname string) []string {
	var res []string
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Errorf("getDefaultRouters failed to find %s: %s",
			ifname, err)
		return res
	}
	ifindex := link.Attrs().Index
	table := types.GetDefaultRouteTable()
	// Note that a default route is represented as nil Dst
	filter := netlink.Route{Table: table, LinkIndex: ifindex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Errorf("getDefaultRouters: for ifname %s RouteList failed: %v\n", ifname, err)
		return res
	}
	// log.Debugf("getDefaultRouters(%s) - got %d", ifname, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		// log.Debugf("getDefaultRouters route dest %v", rt.Dst)
		res = append(res, rt.Gw.String())
	}
	return res
}

// Use the ifname/vifname to find the overlay or underlay status
// and from there the (ip, allocated, mac) addresses for the app
func getAppIP(ctx *zedagentContext, aiStatus *types.AppInstanceStatus,
	vifname string) (string, bool, string) {

	log.Debugf("getAppIP(%s, %s)", aiStatus.Key(), vifname)
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.VifUsed != vifname {
			continue
		}
		log.Debugf("getAppIP(%s, %s) found underlay %s assigned %v mac %s",
			aiStatus.Key(), vifname, ulStatus.AllocatedIPAddr, ulStatus.Assigned, ulStatus.Mac)
		return ulStatus.AllocatedIPAddr, ulStatus.Assigned, ulStatus.Mac
	}
	for _, olStatus := range aiStatus.OverlayNetworks {
		if olStatus.VifUsed != vifname {
			continue
		}
		log.Debugf("getAppIP(%s, %s) found overlay %s assigned %v mac %s",
			aiStatus.Key(), vifname,
			olStatus.EID.String(), olStatus.Assigned, olStatus.Mac)
		return olStatus.EID.String(), olStatus.Assigned, olStatus.Mac
	}
	return "", false, ""
}
