// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Push metrics to zedcloud

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/metrics"
	zmet "github.com/lf-edge/eve/api/go/metrics" // zinfo and zmet here
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
)

func handleDiskMetricModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*zedagentContext)
	ctx.iteration++
	path := status.DiskPath
	log.Infof("handleDiskMetricModify: %s", path)
}

func handleDiskMetricDelete(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*zedagentContext)
	ctx.iteration++
	path := status.DiskPath
	log.Infof("handleDiskMetricModify: %s", path)
}

func lookupDiskMetric(ctx *zedagentContext, diskPath string) *types.DiskMetric {
	diskPath = types.PathToKey(diskPath)
	sub := ctx.subDiskMetric
	m, _ := sub.Get(diskPath)
	if m == nil {
		return nil
	}
	metric := m.(types.DiskMetric)
	return &metric
}

func getAllDiskMetrics(ctx *zedagentContext) []*types.DiskMetric {
	var retList []*types.DiskMetric
	log.Debugf("getAllDiskMetrics")
	sub := ctx.subDiskMetric
	items := sub.GetAll()
	for _, st := range items {
		status := st.(types.DiskMetric)
		retList = append(retList, &status)
	}
	log.Debugf("getAllDiskMetrics: Done")
	return retList
}

func handleAppDiskMetricModify(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.AppDiskMetric)
	ctx := ctxArg.(*zedagentContext)
	ctx.iteration++
	log.Infof("handleAppDiskMetricModify: Received %s", status.DiskPath)
}

func handleAppDiskMetricDelete(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.AppDiskMetric)
	ctx := ctxArg.(*zedagentContext)
	ctx.iteration++
	log.Infof("handleAppDiskMetricDelete: %s", status.DiskPath)
}

func lookupAppDiskMetric(ctx *zedagentContext, diskPath string) *types.AppDiskMetric {
	diskPath = types.PathToKey(diskPath)
	sub := ctx.subAppDiskMetric
	m, _ := sub.Get(diskPath)
	if m == nil {
		return nil
	}
	metric := m.(types.AppDiskMetric)
	return &metric
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
	ctx.ps.StillRunning(agentName+"metrics", warningTime, errorTime)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			iteration++
			publishMetrics(ctx, iteration)
			ctx.ps.CheckMaxTimeTopic(agentName+"metrics", "publishMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(agentName+"metrics", warningTime, errorTime)
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
	ReportDeviceMetric.Memory.AvailPercentage = 100.0 - (usedPercent)
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
		deviceLogMetric.InputSources = make(map[string]uint64)
		for source, val := range logMetrics.DeviceLogInput {
			deviceLogMetric.InputSources[source] = val
		}
		ReportDeviceMetric.Log = deviceLogMetric
	}
	log.Debugln("log metrics: ", ReportDeviceMetric.Log)

	// Collect zedcloud metrics from ourselves and other agents
	cms := types.MetricsMap{} // Start empty
	zedagentMetrics := zedcloud.GetCloudMetrics(log)
	if zedagentMetrics != nil {
		cms = zedcloud.Append(cms, zedagentMetrics)
	}
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
			urlMet.TotalTimeSpent = um.TotalTimeSpent
			metric.UrlMetrics = append(metric.UrlMetrics, urlMet)
		}
		ReportDeviceMetric.Zedcloud = append(ReportDeviceMetric.Zedcloud,
			&metric)
	}

	// collect CipherMetric from agents and report
	// Collect zedcloud metrics from ourselves and other agents
	cipherMetrics := cipher.GetCipherMetrics()
	if cipherMetricsDL != nil {
		cipherMetrics = cipher.Append(cipherMetrics, cipherMetricsDL)
	}
	if cipherMetricsDM != nil {
		cipherMetrics = cipher.Append(cipherMetrics, cipherMetricsDM)
	}
	if cipherMetricsNim != nil {
		cipherMetrics = cipher.Append(cipherMetrics, cipherMetricsNim)
	}
	for agentName, cm := range cipherMetrics {
		log.Debugf("Cipher metrics for %s: %+v", agentName, cm)
		metric := metrics.CipherMetric{AgentName: agentName,
			FailureCount: cm.FailureCount,
			SuccessCount: cm.SuccessCount,
		}
		if !cm.LastFailure.IsZero() {
			lf, _ := ptypes.TimestampProto(cm.LastFailure)
			metric.LastFailure = lf
		}
		if !cm.LastSuccess.IsZero() {
			ls, _ := ptypes.TimestampProto(cm.LastSuccess)
			metric.LastSuccess = ls
		}
		for i := range cm.TypeCounters {
			tc := metrics.TypeCounter{
				ErrorCode: metrics.CipherError(i),
				Count:     cm.TypeCounters[i],
			}
			metric.Tc = append(metric.Tc, &tc)
		}
		ReportDeviceMetric.Cipher = append(ReportDeviceMetric.Cipher,
			&metric)
	}

	var persistUsage uint64
	for _, diskMetric := range getAllDiskMetrics(ctx) {
		var diskPath, mountPath string
		if diskMetric.IsDir {
			mountPath = diskMetric.DiskPath
		} else {
			diskPath = diskMetric.DiskPath
		}
		metric := metrics.DiskMetric{
			Disk:       diskPath,
			MountPath:  mountPath,
			ReadBytes:  utils.RoundToMbytes(diskMetric.ReadBytes),
			WriteBytes: utils.RoundToMbytes(diskMetric.WriteBytes),
			ReadCount:  diskMetric.ReadCount,
			WriteCount: diskMetric.WriteCount,
			Total:      utils.RoundToMbytes(diskMetric.TotalBytes),
			Used:       utils.RoundToMbytes(diskMetric.UsedBytes),
			Free:       utils.RoundToMbytes(diskMetric.FreeBytes),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
		if diskMetric.DiskPath == types.PersistDir {
			persistUsage = diskMetric.UsedBytes
		}
	}
	log.Debugf("DirPaths in persist, elapse sec %v", time.Since(startPubTime).Seconds())

	// Determine how much we use in /persist and how much of it is
	// for the benefits of applications
	var persistAppUsage uint64
	for _, path := range types.AppPersistPaths {
		diskMetric := lookupDiskMetric(ctx, path)
		if diskMetric != nil {
			persistAppUsage += diskMetric.UsedBytes
		}
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
		ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage = 100.0 - (dm.UsedMemoryPercent)
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

		for _, vrs := range aiStatus.VolumeRefStatusList {
			appDiskDetails := new(metrics.AppDiskMetric)
			if vrs.ActiveFileLocation == "" {
				log.Infof("ActiveFileLocation is empty for %s", vrs.Key())
			} else {
				err := getDiskInfo(ctx, vrs, appDiskDetails)
				if err != nil {
					log.Warnf("getDiskInfo(%s) failed %v",
						vrs.ActiveFileLocation, err)
					continue
				}
			}
			ReportAppMetric.Disk = append(ReportAppMetric.Disk,
				appDiskDetails)
		}

		acMetric := lookupAppContainerMetric(ctx, aiStatus.UUIDandVersion.UUID.String())
		// the new protocol is always fill in at least the module name to indicate
		// it has not disappeared yet, even we don't have new info on metrics
		if acMetric != nil {
			for _, stats := range acMetric.StatsList { // go through each container
				appContainerMetric := new(metrics.AppContainerMetric)
				appContainerMetric.AppContainerName = stats.ContainerName

				// fill in the new metrics info for each module
				if acMetric.CollectTime.Sub(ctx.appContainerStatsTime) > 0 {
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
				}

				ReportAppMetric.Container = append(ReportAppMetric.Container, appContainerMetric)
			}
			ctx.appContainerStatsTime = acMetric.CollectTime
		}

		ReportMetrics.Am = append(ReportMetrics.Am, ReportAppMetric)
	}

	createNetworkInstanceMetrics(ctx, ReportMetrics)
	createVolumeInstanceMetrics(ctx, ReportMetrics)

	log.Debugf("PublishMetricsToZedCloud sending %s", ReportMetrics)
	SendMetricsProtobuf(ReportMetrics, iteration)
	log.Debugf("publishMetrics: after send, total elapse sec %v", time.Since(startPubTime).Seconds())
}

func getDiskInfo(ctx *zedagentContext, vrs types.VolumeRefStatus, appDiskDetails *metrics.AppDiskMetric) error {
	appDiskMetric := lookupAppDiskMetric(ctx, vrs.ActiveFileLocation)
	if appDiskMetric == nil {
		err := fmt.Errorf("getDiskInfo: No AppDiskMetric found for %s", vrs.ActiveFileLocation)
		log.Error(err)
		return err
	}
	appDiskDetails.Disk = vrs.ActiveFileLocation
	appDiskDetails.Used = utils.RoundToMbytes(appDiskMetric.UsedBytes)
	appDiskDetails.Provisioned = utils.RoundToMbytes(appDiskMetric.ProvisionedBytes)
	appDiskDetails.DiskType = appDiskMetric.DiskType
	appDiskDetails.Dirty = appDiskMetric.Dirty
	return nil
}

func getVolumeResourcesInfo(ctx *zedagentContext, volStatus *types.VolumeStatus, volumeResourcesDetails *info.VolumeResources) error {
	appDiskMetric := lookupAppDiskMetric(ctx, volStatus.FileLocation)
	if appDiskMetric == nil {
		err := fmt.Errorf("getVolumeResourcesInfo: No AppDiskMetric found for %s", volStatus.FileLocation)
		log.Error(err)
		return err
	}

	volumeResourcesDetails.CurSizeBytes = appDiskMetric.UsedBytes
	volumeResourcesDetails.MaxSizeBytes = appDiskMetric.ProvisionedBytes
	return nil
}

func getSecurityInfo(ctx *zedagentContext) *info.SecurityInfo {

	si := new(info.SecurityInfo)
	// Deterime sha of the root CA cert used for object signing and
	// encryption
	caCert1, err := ioutil.ReadFile(types.RootCertFileName)
	if err != nil {
		log.Error(err)
	} else {
		hasher := sha256.New()
		hasher.Write(caCert1)
		si.ShaRootCa = hasher.Sum(nil)
	}
	// Add the sha of the root CAs used for TLS
	// Note that we have the sha in a logical symlink so we
	// just read that file.
	line, err := ioutil.ReadFile(types.V2TLSCertShaFilename)
	if err != nil {
		log.Error(err)
	} else {
		shaStr := strings.TrimSpace(string(line))
		sha, err := hex.DecodeString(shaStr)
		if err != nil {
			log.Errorf("DecodeString %s failed: %s", shaStr, err)
		} else {
			si.ShaTlsRootCa = sha
		}
	}
	log.Debugf("getSecurityInfo returns %+v", si)
	return si
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
		ifNames := (*aiStatus).GetAppInterfaceList()
		log.Debugf("ReportAppInfo: domainName %s ifs %v",
			aiStatus.DomainName, ifNames)
		for _, ifname := range ifNames {
			networkInfo := new(info.ZInfoNetwork)
			networkInfo.LocalName = *proto.String(ifname)
			ip, allocated, macAddr, ipAddrMismatch := getAppIP(ctx, aiStatus,
				ifname)
			networkInfo.IPAddrs = make([]string, 1)
			networkInfo.IPAddrs[0] = *proto.String(ip)
			networkInfo.MacAddr = *proto.String(macAddr)
			networkInfo.Up = allocated
			networkInfo.IpAddrMisMatch = ipAddrMismatch
			name := appIfnameToName(aiStatus, ifname)
			log.Debugf("app %s/%s localName %s devName %s",
				aiStatus.Key(), aiStatus.DisplayName,
				ifname, name)
			networkInfo.DevName = *proto.String(name)
			ReportAppInfo.Network = append(ReportAppInfo.Network,
				networkInfo)
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

	zedcloud.RemoveDeferred(zedcloudCtx, uuid)
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
		zedcloud.SetDeferred(zedcloudCtx, uuid, buf, size, statusUrl,
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

		ContentResourcesInfo := new(info.ContentResources)
		ContentResourcesInfo.CurSizeBytes = uint64(ctStatus.TotalSize)
		ReportContentInfo.Resources = ContentResourcesInfo

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

	zedcloud.RemoveDeferred(zedcloudCtx, uuid)
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
		zedcloud.SetDeferred(zedcloudCtx, uuid, buf, size, statusURL,
			true)
	}
}

// PublishVolumeToZedCloud is called per change, hence needs to try over all management ports
// When volume status is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishVolumeToZedCloud(ctx *zedagentContext, uuid string,
	volStatus *types.VolumeStatus, iteration int) {

	log.Infof("PublishVolumeToZedCloud uuid %s", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	volumeType := new(info.ZInfoTypes)
	*volumeType = info.ZInfoTypes_ZiVolume
	ReportInfo.Ztype = *volumeType
	ReportInfo.DevId = *proto.String(zcdevUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportVolumeInfo := new(info.ZInfoVolume)

	ReportVolumeInfo.Uuid = uuid
	ReportVolumeInfo.State = info.ZSwState_INITIAL
	if volStatus != nil {
		ReportVolumeInfo.DisplayName = volStatus.DisplayName
		ReportVolumeInfo.State = volStatus.State.ZSwState()

		if !volStatus.ErrorTime.IsZero() {
			errInfo := encodeErrorInfo(
				volStatus.ErrorAndTimeWithSource.ErrorAndTime())
			ReportVolumeInfo.VolumeErr = errInfo
		}

		if volStatus.FileLocation == "" {
			log.Infof("FileLocation is empty for %s", volStatus.Key())
		} else {
			VolumeResourcesInfo := new(info.VolumeResources)
			err := getVolumeResourcesInfo(ctx, volStatus, VolumeResourcesInfo)
			if err != nil {
				log.Errorf("getVolumeResourceInfo(%s) failed %v",
					volStatus.VolumeID, err)
			} else {
				ReportVolumeInfo.Resources = VolumeResourcesInfo
			}
		}

		ReportVolumeInfo.ProgressPercentage = uint32(volStatus.Progress)
		ReportVolumeInfo.GenerationCount = volStatus.GenerationCounter
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Vinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Vinfo); ok {
		x.Vinfo = ReportVolumeInfo
	}

	log.Infof("PublishVolumeToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishVolumeToZedCloud proto marshaling error: ", err)
	}
	statusURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")

	zedcloud.RemoveDeferred(zedcloudCtx, uuid)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusURL, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishVolumeToZedCloud failed: %s", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(zedcloudCtx, uuid, buf, size, statusURL,
			true)
	}
}

// PublishBlobInfoToZedCloud is called per change, hence needs to try over all management ports
// When blob Status is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishBlobInfoToZedCloud(ctx *zedagentContext, blobSha string, blobStatus *types.BlobStatus, iteration int) {
	log.Infof("PublishBlobInfoToZedCloud blobSha %v", blobSha)
	var ReportInfo = &info.ZInfoMsg{}

	contentType := new(info.ZInfoTypes)
	*contentType = info.ZInfoTypes_ZiBlobList
	ReportInfo.Ztype = *contentType
	ReportInfo.DevId = *proto.String(zcdevUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportBlobInfoList := new(info.ZInfoBlobList)

	ReportBlobInfo := new(info.ZInfoBlob)

	ReportBlobInfo.Sha256 = blobSha
	if blobStatus != nil {
		ReportBlobInfo.State = blobStatus.State.ZSwState()
		ReportBlobInfo.ProgressPercentage = blobStatus.GetDownloadedPercentage()
		ReportBlobInfo.Usage = &info.UsageInfo{RefCount: uint32(blobStatus.RefCount)}
	}
	ReportBlobInfoList.Blob = append(ReportBlobInfoList.Blob, ReportBlobInfo)

	ReportInfo.InfoContent = new(info.ZInfoMsg_Binfo)
	if blobInfoList, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Binfo); ok {
		blobInfoList.Binfo = ReportBlobInfoList
	}

	log.Infof("PublishBlobInfoToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishBlobInfoToZedCloud proto marshaling error: ", err)
	}
	statusURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")

	zedcloud.RemoveDeferred(zedcloudCtx, blobSha)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusURL, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishBlobInfoToZedCloud failed: %s", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(zedcloudCtx, blobSha, buf, size, statusURL,
			true)
	}
}

func appIfnameToName(aiStatus *types.AppInstanceStatus, vifname string) string {
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.VifUsed == vifname {
			return ulStatus.Name
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
	resp, _, _, err := zedcloud.SendOnAllIntf(zedcloudCtx, url,
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
	_, _, rtf, err := zedcloud.SendOnAllIntf(zedcloudCtx, metricsUrl,
		size, buf, iteration, bailOnHTTPErr)
	if err != nil {
		// Hopefully next timeout will be more successful
		log.Errorf("SendMetricsProtobuf status %d failed: %s", rtf, err)
		return
	} else {
		writeSentMetricsProtoMessage(data)
	}
}

// Use the ifname/vifname to find the underlay status
// and from there the (ip, allocated, mac) addresses for the app
func getAppIP(ctx *zedagentContext, aiStatus *types.AppInstanceStatus,
	vifname string) (string, bool, string, bool) {

	log.Debugf("getAppIP(%s, %s)", aiStatus.Key(), vifname)
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.VifUsed != vifname {
			continue
		}
		log.Debugf("getAppIP(%s, %s) found underlay %s assigned %v mac %s",
			aiStatus.Key(), vifname, ulStatus.AllocatedIPAddr, ulStatus.Assigned, ulStatus.Mac)
		return ulStatus.AllocatedIPAddr, ulStatus.Assigned, ulStatus.Mac, ulStatus.IPAddrMisMatch
	}
	return "", false, "", false
}

func createVolumeInstanceMetrics(ctx *zedagentContext, reportMetrics *metrics.ZMetricMsg) {
	log.Debugf("Volume instance metrics started")
	sub := ctx.getconfigCtx.subVolumeStatus
	volumelist := sub.GetAll()
	if volumelist == nil || len(volumelist) == 0 {
		return
	}
	for _, volume := range volumelist {
		volumeStatus := volume.(types.VolumeStatus)
		volumeMetric := new(metrics.ZMetricVolume)
		volumeMetric.Uuid = volumeStatus.VolumeID.String()
		volumeMetric.DisplayName = volumeStatus.DisplayName
		if volumeStatus.FileLocation == "" {
			log.Infof("FileLocation is empty for %s", volumeStatus.Key())
		} else {
			getVolumeResourcesMetrics(ctx, volumeStatus.FileLocation, volumeMetric)
		}
		reportMetrics.Vm = append(reportMetrics.Vm, volumeMetric)
	}
	log.Debugf("Volume instance metrics done: %v", reportMetrics.Vm)
}

func getVolumeResourcesMetrics(ctx *zedagentContext, name string, volumeMetric *metrics.ZMetricVolume) error {
	appDiskMetric := lookupAppDiskMetric(ctx, name)
	if appDiskMetric == nil {
		err := fmt.Errorf("getVolumeResourcesMetrics: No AppDiskMetric found for %s", name)
		log.Error(err)
		return err
	}
	volumeMetric.UsedBytes = appDiskMetric.UsedBytes
	volumeMetric.TotalBytes = appDiskMetric.ProvisionedBytes
	volumeMetric.FreeBytes = appDiskMetric.ProvisionedBytes - appDiskMetric.UsedBytes
	return nil
}

func createNetworkInstanceMetrics(ctx *zedagentContext, reportMetrics *zmet.ZMetricMsg) {

	sub := ctx.subNetworkInstanceMetrics
	metlist := sub.GetAll()
	if metlist == nil || len(metlist) == 0 {
		return
	}
	for _, met := range metlist {
		metrics := met.(types.NetworkInstanceMetrics)
		metricInstance := protoEncodeNetworkInstanceMetricProto(metrics)
		reportMetrics.Nm = append(reportMetrics.Nm, metricInstance)
	}
	log.Debugln("network instance metrics: ", reportMetrics.Nm)
}

func protoEncodeNetworkInstanceMetricProto(status types.NetworkInstanceMetrics) *zmet.ZMetricNetworkInstance {

	metric := new(zmet.ZMetricNetworkInstance)
	metric.NetworkID = status.Key()
	metric.NetworkVersion = status.UUIDandVersion.Version
	metric.Displayname = status.DisplayName
	metric.InstType = uint32(status.Type)
	switch status.Type {
	case types.NetworkInstanceTypeCloud:
		protoEncodeVpnInstanceMetric(status, metric)

	default:
		protoEncodeGenericInstanceMetric(status, metric)
	}

	return metric
}
