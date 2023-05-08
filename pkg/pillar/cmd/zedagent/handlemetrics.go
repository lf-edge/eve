// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Push metrics to zedcloud

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/metrics"
	zmet "github.com/lf-edge/eve/api/go/metrics" // zinfo and zmet here
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
	"google.golang.org/protobuf/proto"
)

func handleDiskMetricCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDiskMetricImpl(ctxArg, key, statusArg)
}

func handleDiskMetricModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDiskMetricImpl(ctxArg, key, statusArg)
}

func handleDiskMetricImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*zedagentContext)
	ctx.iteration++
	path := status.DiskPath
	log.Functionf("handleDiskMetricImpl: %s", path)
}

func handleDiskMetricDelete(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*zedagentContext)
	ctx.iteration++
	path := status.DiskPath
	log.Functionf("handleDiskMetricModify: %s", path)
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
	log.Tracef("getAllDiskMetrics")
	sub := ctx.subDiskMetric
	items := sub.GetAll()
	for _, st := range items {
		status := st.(types.DiskMetric)
		retList = append(retList, &status)
	}
	log.Tracef("getAllDiskMetrics: Done")
	return retList
}

func handleAppDiskMetricCreate(ctxArg interface{}, key string, _ interface{}) {
	ctx := ctxArg.(*zedagentContext)

	// if AppDiskMetric create event come after VolumeStatus available
	// we should publish updated numbers based on AppDiskMetric
	volumeStatusList := ctx.getconfigCtx.subVolumeStatus.GetAll()
	for _, s := range volumeStatusList {
		volumeStatus, ok := s.(types.VolumeStatus)
		if !ok {
			log.Error("unexpected type in subVolumeStatus")
			continue
		}
		if volumeStatus.FileLocation == "" {
			continue
		}
		if key != types.PathToKey(volumeStatus.FileLocation) {
			continue
		}
		uuidStr := volumeStatus.VolumeID.String()
		PublishVolumeToZedCloud(ctx, uuidStr, &volumeStatus,
			ctx.iteration, AllDest)
	}
	log.Functionf("handleAppDiskMetricCreate: %s", key)
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

func encodeErrorInfo(et types.ErrorDescription) *info.ErrorInfo {
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
	errInfo.Severity = info.Severity(et.ErrorSeverity)
	errInfo.RetryCondition = et.ErrorRetryCondition
	errInfo.Entities = make([]*info.DeviceEntity, len(et.ErrorEntities))
	for i, el := range et.ErrorEntities {
		errInfo.Entities[i] = &info.DeviceEntity{EntityId: el.EntityID, Entity: info.Entity(el.EntityType)}
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

// Run a periodic post of the metrics and info to an LOC if we have one
func metricsAndInfoTimerTask(ctx *zedagentContext, handleChannel chan interface{}) {
	iteration := 0
	log.Functionln("starting report metrics/info timer task")
	publishMetrics(ctx, iteration)

	interval := time.Duration(ctx.globalConfig.GlobalValueInt(types.MetricInterval)) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	wdName := agentName + "metrics"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			iteration++
			publishMetrics(ctx, iteration)
			ctx.ps.CheckMaxTimeTopic(wdName, "publishMetrics", start,
				warningTime, errorTime)

			locConfig := ctx.getconfigCtx.locConfig
			if locConfig != nil {
				// Publish all info by timer only for LOC
				triggerPublishAllInfo(ctx, LOCDest)
			}

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// maybeUpdateMetricsTimer is responsible of calling updateMetricsTimer.
// This method handles 2 scenarios:
//  1. Current metrics publish interval > new metrics publish interval in GlobalConfig
//     For instance, if currentMetricInterval = 300s and latestMetricTickerInterval = 200s,
//     the controller will be expecting a metrics every 300s. So increasing the frequency
//     immediately to 200s will not result in controller marking the edge-node as suspect
//     in between.
//  2. Current metrics publish interval < new metrics publish interval in GlobalConfig
//     For instance, if currentMetricInterval = 200s and latestMetricTickerInterval = 300s,
//     the controller will be expecting a metrics every 200s. So decreasing the frequency to
//     300s can result in controller marking the edge-node as suspect in between. To avoid this,
//     we have to make sure that the controller is notified  to expect a metrics every 300s before
//     updating our publish frequency. forceUpdate should be true only after we've successfully
//     notified new frequency to the controller.
func maybeUpdateMetricsTimer(ctx *getconfigContext, forceUpdate bool) {
	latestMetricsInterval := ctx.zedagentCtx.globalConfig.GlobalValueInt(types.MetricInterval)
	log.Functionf("maybeUpdateMetricsTimer: currentMetricInterval %v, latestMetricsInterval %v, forceUpdate: %v",
		ctx.currentMetricInterval, latestMetricsInterval, forceUpdate)
	if ctx.currentMetricInterval > latestMetricsInterval {
		log.Tracef("maybeUpdateMetricsTimer: updating metrics publish interval %v seconds",
			latestMetricsInterval)
		updateMetricsTimer(ctx, latestMetricsInterval)
	} else if ctx.currentMetricInterval < latestMetricsInterval {
		if forceUpdate {
			log.Tracef("maybeUpdateMetricsTimer: updating metrics publish interval %v seconds",
				latestMetricsInterval)
			updateMetricsTimer(ctx, latestMetricsInterval)
		} else {
			// Force an immediate timeout to publish metrics.
			if ctx.metricsTickerHandle != nil {
				flextimer.TickNow(ctx.metricsTickerHandle)
			}
		}
	}
}

// Called when globalConfig changes
// Assumes the caller has verifier that the interval has changed
func updateMetricsTimer(ctx *getconfigContext, metricInterval uint32) {

	if ctx.metricsTickerHandle == nil {
		log.Warnf("updateMetricsTimer: no metricsTickerHandle yet")
		return
	}
	interval := time.Duration(metricInterval) * time.Second
	log.Functionf("updateMetricsTimer() change to %v", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(ctx.metricsTickerHandle,
		time.Duration(min), time.Duration(max))
	ctx.currentMetricInterval = metricInterval
	// Force an immediate timeout since timer could have decreased
	flextimer.TickNow(ctx.metricsTickerHandle)
}

// Key is device UUID for host and app instance UUID for app instances
// Returns DomainMetric
func lookupDomainMetric(ctx *zedagentContext, uuidStr string) *types.DomainMetric {
	sub := ctx.getconfigCtx.subDomainMetric
	m, _ := sub.Get(uuidStr)
	if m == nil {
		log.Functionf("lookupDomainMetric(%s) not found", uuidStr)
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

	ReportMetrics.DevID = *proto.String(devUUID.String())
	ReportZmetric := new(metrics.ZmetricTypes)
	*ReportZmetric = metrics.ZmetricTypes_ZmDevice

	// This will be overridden with the timestamp for the CPU metrics
	// below to make CPU usage calculations more accurate
	ReportMetrics.AtTimeStamp = ptypes.TimestampNow()

	info, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s", err)
	}
	log.Tracef("uptime %d = %d days",
		info.Uptime, info.Uptime/(3600*24))
	log.Tracef("Booted at %v", time.Unix(int64(info.BootTime), 0).UTC())

	// Note that uptime is seconds we've been up. We're converting
	// to a timestamp. That better not be interpreted as a time since
	// the epoch
	uptime, _ := ptypes.TimestampProto(
		time.Unix(int64(info.Uptime), 0).UTC())
	ReportDeviceMetric.CpuMetric.UpTime = uptime

	// Memory related info for the device
	var totalMemory, freeMemory, usedEveMB uint64
	sub := ctx.getconfigCtx.subHostMemory
	m, _ := sub.Get("global")
	if m != nil {
		metric := m.(types.HostMemory)
		totalMemory = metric.TotalMemoryMB
		freeMemory = metric.FreeMemoryMB
		usedEveMB = metric.UsedEveMB + metric.KmemUsedEveMB
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
	log.Tracef("Device Memory from xl info: %v %v %v %v",
		ReportDeviceMetric.Memory.UsedMem,
		ReportDeviceMetric.Memory.AvailMem,
		ReportDeviceMetric.Memory.UsedPercentage,
		ReportDeviceMetric.Memory.AvailPercentage)

	// Use the network metrics from zedrouter subscription
	// Only report stats for the ports in DeviceNetworkStatus
	labelList := types.ReportLogicallabels(*deviceNetworkStatus)
	for _, label := range labelList {
		var metric *types.NetworkMetric
		ports := deviceNetworkStatus.GetPortsByLogicallabel(label)
		if len(ports) == 0 {
			continue
		}
		p := ports[0]
		if !p.IsL3Port {
			// metrics for ports from lower layers are not reported
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

	aclMetric := new(metrics.AclMetric)
	aclMetric.TotalRuleCount = networkMetrics.TotalRuleCount
	ReportDeviceMetric.Acl = aclMetric

	ReportDeviceMetric.Cellular = getCellularMetrics(ctx)

	zedboxStats := new(metrics.ZedboxStats)
	zedboxStats.NumGoRoutines = uint32(runtime.NumGoroutine()) // number of zedbox goroutines
	ReportDeviceMetric.Zedbox = zedboxStats

	// Transfer to a local copy in since metrics updates are done concurrently
	cms := types.MetricsMap{}
	ctx.zedcloudMetrics.AddInto(log, cms)
	clientMetrics.AddInto(cms)
	downloaderMetrics.AddInto(cms)
	loguploaderMetrics.AddInto(cms)
	diagMetrics.AddInto(cms)
	nimMetrics.AddInto(cms)
	zrouterMetrics.AddInto(cms)
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
			log.Tracef("CloudMetrics[%s] url %s %v",
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
			urlMet.SessResumeCount = um.SessionResume
			metric.UrlMetrics = append(metric.UrlMetrics, urlMet)
		}
		ReportDeviceMetric.Zedcloud = append(ReportDeviceMetric.Zedcloud,
			&metric)
	}

	nlm := &zmet.NewlogMetric{
		FailedToSend:        newlogMetrics.FailedToSend,
		TotalBytesUpload:    newlogMetrics.TotalBytesUpload,
		Num4XxResponses:     newlogMetrics.Num4xxResponses,
		CurrentUploadIntv:   newlogMetrics.CurrUploadIntvSec,
		LogfileTimeout:      newlogMetrics.LogfileTimeoutSec,
		MaxGzipFileSize:     newlogMetrics.MaxGzipSize,
		AvgGzipFileSize:     newlogMetrics.AvgGzipSize,
		MimUploadMsec:       newlogMetrics.Latency.MinUploadMsec,
		MaxUploadMsec:       newlogMetrics.Latency.MaxUploadMsec,
		AvgUploadMsec:       newlogMetrics.Latency.AvgUploadMsec,
		LastUploadMsec:      newlogMetrics.Latency.CurrUploadMsec,
		CurrentCPULoadPct:   newlogMetrics.ServerStats.CurrCPULoadPCT,
		AverageCPULoadPct:   newlogMetrics.ServerStats.AvgCPULoadPCT,
		CurrentProcessDelay: newlogMetrics.ServerStats.CurrProcessMsec,
		AverageProcessDelay: newlogMetrics.ServerStats.AvgProcessMsec,
		GzipFilesRemoved:    newlogMetrics.NumGZipFileRemoved,
		TooManyRequest:      newlogMetrics.NumTooManyRequest,
		SkipUploadAppFile:   newlogMetrics.NumSkipUploadAppFile,
	}
	if !newlogMetrics.FailSentStartTime.IsZero() {
		nlm.FailSentStartTime, _ = ptypes.TimestampProto(newlogMetrics.FailSentStartTime)
	}

	devM := &zmet.LogfileMetrics{
		NumGzipFileSent:      newlogMetrics.DevMetrics.NumGZipFilesSent,
		NumGzipBytesWrite:    newlogMetrics.DevMetrics.NumGZipBytesWrite,
		NumBytesWrite:        newlogMetrics.DevMetrics.NumBytesWrite,
		NumGzipFileInDir:     newlogMetrics.DevMetrics.NumGzipFileInDir,
		NumInputEvent:        newlogMetrics.DevMetrics.NumInputEvent,
		NumGzipFileRetry:     newlogMetrics.DevMetrics.NumGZipFileRetry,
		NumGzipFileKeptLocal: newlogMetrics.DevMetrics.NumGZipFileKeptLocal,
	}
	if !newlogMetrics.DevMetrics.RecentUploadTimestamp.IsZero() {
		devM.RecentGzipFileTime, _ = ptypes.TimestampProto(newlogMetrics.DevMetrics.RecentUploadTimestamp)
	}
	if !newlogMetrics.DevMetrics.LastGZipFileSendTime.IsZero() {
		devM.LastGzipFileSendTime, _ = ptypes.TimestampProto(newlogMetrics.DevMetrics.LastGZipFileSendTime)
	}
	nlm.DeviceMetrics = devM

	appM := &zmet.LogfileMetrics{
		NumGzipFileSent:      newlogMetrics.AppMetrics.NumGZipFilesSent,
		NumGzipBytesWrite:    newlogMetrics.AppMetrics.NumGZipBytesWrite,
		NumBytesWrite:        newlogMetrics.AppMetrics.NumBytesWrite,
		NumGzipFileInDir:     newlogMetrics.AppMetrics.NumGzipFileInDir,
		NumInputEvent:        newlogMetrics.AppMetrics.NumInputEvent,
		NumGzipFileRetry:     newlogMetrics.AppMetrics.NumGZipFileRetry,
		NumGzipFileKeptLocal: newlogMetrics.AppMetrics.NumGZipFileKeptLocal,
	}
	if !newlogMetrics.AppMetrics.RecentUploadTimestamp.IsZero() {
		appM.RecentGzipFileTime, _ = ptypes.TimestampProto(newlogMetrics.AppMetrics.RecentUploadTimestamp)
	}
	if !newlogMetrics.AppMetrics.LastGZipFileSendTime.IsZero() {
		appM.LastGzipFileSendTime, _ = ptypes.TimestampProto(newlogMetrics.AppMetrics.LastGZipFileSendTime)
	}
	nlm.AppMetrics = appM

	nlm.Top10InputSources = make(map[string]uint32)
	for source, val := range newlogMetrics.DevTop10InputBytesPCT {
		nlm.Top10InputSources[source] = val
	}
	ReportDeviceMetric.Newlog = nlm
	log.Tracef("publishMetrics: newlog-metrics %+v", nlm)

	// combine CipherMetric from all agents and report
	cipherMetrics := []types.CipherMetrics{
		cipherMetricsDL,
		cipherMetricsDM,
		cipherMetricsNim,
		cipherMetricsZR,
	}
	for _, cm := range cipherMetrics {
		log.Functionf("Cipher metrics for %s: %+v", cm.AgentName, cm)
		metric := metrics.CipherMetric{AgentName: cm.AgentName,
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
			if tc.Count != 0 {
				metric.Tc = append(metric.Tc, &tc)
			}
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
	log.Tracef("DirPaths in persist, elapse sec %v", time.Since(startPubTime).Seconds())

	// Determine how much we use in /persist and how much of it is
	// for the benefits of applications
	var persistAppUsage uint64
	for _, path := range types.AppPersistPaths {
		diskMetric := lookupDiskMetric(ctx, path)
		if diskMetric != nil {
			persistAppUsage += diskMetric.UsedBytes
		}
	}
	log.Tracef("persistAppUsage %d, elapse sec %v", persistAppUsage, time.Since(startPubTime).Seconds())

	persistOverhead := persistUsage - persistAppUsage
	// Convert to MB
	runtimeStorageOverhead := types.RoundupToKB(types.RoundupToKB(persistOverhead))
	appRunTimeStorage := types.RoundupToKB(types.RoundupToKB(persistAppUsage))
	log.Tracef("runtimeStorageOverhead %d MB, appRunTimeStorage %d MB",
		runtimeStorageOverhead, appRunTimeStorage)
	ReportDeviceMetric.RuntimeStorageOverheadMB = runtimeStorageOverhead
	ReportDeviceMetric.AppRunTimeStorageMB = appRunTimeStorage

	const nanoSecToSec uint64 = 1000000000

	// Get device info using nil UUID
	dm := lookupDomainMetric(ctx, nilUUID.String())
	if dm != nil {
		log.Tracef("host CPU: %d, at %v, percent used %d",
			dm.CPUTotalNs, dm.LastHeard, (100*dm.CPUTotalNs)/uint64(info.Uptime))
		// Override the time of the report with the time from
		// domainmgr
		if !dm.LastHeard.IsZero() {
			lh, _ := ptypes.TimestampProto(dm.LastHeard)
			ReportMetrics.AtTimeStamp = lh
		}

		ReportDeviceMetric.CpuMetric.Total = *proto.Uint64(dm.CPUTotalNs / nanoSecToSec)
		ReportDeviceMetric.CpuMetric.TotalNs = dm.CPUTotalNs

		// Report new DeviceMemoryMetric
		ReportDeviceMetric.DeviceMemory = new(metrics.DeviceMemoryMetric)
		ReportDeviceMetric.DeviceMemory.MemoryMB = uint32(totalMemory)
		// Loop over AppInstanceConfig to get sum for AllocatedAppsMB
		// independent of status; use DomainMetric if it exists since
		// it has the number which includes the qemu overhead.
		var sumKB uint64
		pub := ctx.getconfigCtx.pubAppInstanceConfig
		items := pub.GetAll()
		for _, c := range items {
			aiConfig := c.(types.AppInstanceConfig)

			dm := lookupDomainMetric(ctx, aiConfig.Key())
			if dm != nil {
				sumKB += 1024 * uint64(dm.AllocatedMB)
			} else {
				sumKB += uint64(aiConfig.FixedResources.Memory)
			}
		}
		ReportDeviceMetric.DeviceMemory.AllocatedAppsMB = uint32((sumKB + 1023) / 1024)

		allocatedEve, err := types.GetEveMemoryLimitInBytes()
		if err != nil {
			log.Errorf("GetEveMemoryLimitInBytes failed: %v", err)
		} else {
			ReportDeviceMetric.DeviceMemory.AllocatedEveMB =
				uint32((allocatedEve + 1024*1024 - 1) / (1024 * 1024))
		}
		ReportDeviceMetric.DeviceMemory.UsedEveMB = uint32(usedEveMB)

		// SystemServicesMemoryMB is deprecated and replaced by DeviceMemoryMetric.
		// Report to support there are old controllers
		ReportDeviceMetric.SystemServicesMemoryMB = new(metrics.MemoryMetric)
		ReportDeviceMetric.SystemServicesMemoryMB.UsedMem = dm.UsedMemory
		ReportDeviceMetric.SystemServicesMemoryMB.AvailMem = dm.AvailableMemory
		ReportDeviceMetric.SystemServicesMemoryMB.UsedPercentage = dm.UsedMemoryPercent
		ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage = 100.0 - (dm.UsedMemoryPercent)
		log.Tracef("host Memory: %v %v %v %v",
			ReportDeviceMetric.SystemServicesMemoryMB.UsedMem,
			ReportDeviceMetric.SystemServicesMemoryMB.AvailMem,
			ReportDeviceMetric.SystemServicesMemoryMB.UsedPercentage,
			ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage)
	}

	if !ctx.getconfigCtx.lastReceivedConfig.IsZero() {
		protoTime, err := ptypes.TimestampProto(ctx.getconfigCtx.lastReceivedConfig)
		if err == nil {
			ReportDeviceMetric.LastReceivedConfig = protoTime
		} else {
			log.Errorf("Failed to convert timestamp (%+v) for LastReceivedConfig into TimestampProto. err: %s",
				ctx.getconfigCtx.lastReceivedConfig, err)
		}
	}
	if !ctx.getconfigCtx.lastProcessedConfig.IsZero() {
		protoTime, err := ptypes.TimestampProto(ctx.getconfigCtx.lastProcessedConfig)
		if err == nil {
			ReportDeviceMetric.LastProcessedConfig = protoTime
		} else {
			log.Errorf("Failed to convert timestamp (%+v) for LastProcessedConfig into TimestampProto. err: %s",
				ctx.getconfigCtx.lastProcessedConfig, err)
		}
	}
	ReportDeviceMetric.DormantTimeInSeconds = getDormantTime(ctx)

	// Report metrics from ZFS
	if vault.ReadPersistType() == types.PersistZFS {
		for _, el := range ctx.subZFSPoolMetrics.GetAll() {
			zfsPoolMetrics := el.(types.ZFSPoolMetrics)
			ReportDeviceMetric.StorageMetrics = append(ReportDeviceMetric.StorageMetrics,
				fillStorageMetrics(&zfsPoolMetrics))
		}
	}

	// Report flowlog metrics.
	ctx.flowLogMetrics.Lock()
	ReportDeviceMetric.Flowlog = &metrics.FlowlogMetric{
		Messages:    protoEncodeFlowlogCounters(ctx.flowLogMetrics.Messages),
		Flows:       protoEncodeFlowlogCounters(ctx.flowLogMetrics.Flows),
		DnsRequests: protoEncodeFlowlogCounters(ctx.flowLogMetrics.DNSReqs),
	}
	ctx.flowLogMetrics.Unlock()

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
		// New AppMemoryMetric
		ReportAppMetric.AppMemory = new(metrics.AppMemoryMetric)
		// MemoryMetric is deprecated; keep for old controllers for now
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
			log.Tracef("metrics for %s CPU %d, usedMem %v, availMem %v, availMemPercent %v",
				aiStatus.DomainName, dm.CPUTotalNs, dm.UsedMemory,
				dm.AvailableMemory, dm.UsedMemoryPercent)

			// Deprecated filed in seconds
			ReportAppMetric.Cpu.Total = *proto.Uint64(dm.CPUTotalNs / nanoSecToSec)
			// New field in nanosec.
			ReportAppMetric.Cpu.TotalNs = dm.CPUTotalNs

			// New AppMemoryMetric fields
			ReportAppMetric.AppMemory.AllocatedMB = dm.AllocatedMB
			ReportAppMetric.AppMemory.UsedMB = dm.UsedMemory

			// Deprecated MemoryMetric fields
			ReportAppMetric.Memory.UsedMem = dm.UsedMemory
			ReportAppMetric.Memory.AvailMem = dm.AvailableMemory
			ReportAppMetric.Memory.UsedPercentage = dm.UsedMemoryPercent
			availableMemoryPercent := 100.0 - dm.UsedMemoryPercent
			ReportAppMetric.Memory.AvailPercentage = availableMemoryPercent
		}

		appInterfaceList := aiStatus.GetAppInterfaceList()
		log.Tracef("ReportMetrics: domainName %s ifs %v",
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
			log.Tracef("app %s/%s localname %s name %s",
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
				log.Functionf("ActiveFileLocation is empty for %s", vrs.Key())
				continue
			}
			err := getDiskInfo(ctx, vrs, appDiskDetails)
			if err != nil {
				logData := fmt.Sprintf("getDiskInfo(%s) failed %v",
					vrs.ActiveFileLocation, err)
				if vrs.State >= types.CREATED_VOLUME {
					log.Warn(logData)
				} else {
					log.Function(logData)
				}
				continue
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
					// convert to seconds
					appContainerMetric.Cpu.Total = stats.CPUTotal / nanoSecToSec
					appContainerMetric.Cpu.SystemTotal = stats.SystemCPUTotal / nanoSecToSec
					appContainerMetric.Cpu.TotalNs = stats.CPUTotal

					// New AppMemoryMetric
					appContainerMetric.AppContainerMemory = new(metrics.AppMemoryMetric)
					appContainerMetric.AppContainerMemory.AllocatedMB = stats.AllocatedMem
					appContainerMetric.AppContainerMemory.UsedMB = stats.UsedMem

					// MemoryMetric is deprecated; keep for old controllers for now

					appContainerMetric.Memory = new(metrics.MemoryMetric)
					appContainerMetric.Memory.UsedMem = stats.UsedMem
					// We report the Allocated aka Limit
					// in the AvailMem field, which is confusing
					// but this MemoryMetric is deprecated.
					appContainerMetric.Memory.AvailMem = stats.AllocatedMem

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
	createProcessMetrics(ctx, ReportMetrics)

	log.Tracef("PublishMetricsToZedCloud sending %s", ReportMetrics)
	sendMetricsProtobuf(ctx.getconfigCtx, ReportMetrics, iteration)
	log.Tracef("publishMetrics: after send, total elapse sec %v", time.Since(startPubTime).Seconds())

	// publish the cloud MetricsMap for zedagent for device debugging purpose
	if ctx.zedcloudMetrics != nil {
		ctx.zedcloudMetrics.Publish(log, ctx.pubMetricsMap, "global")
	}
}

func getCellularMetrics(ctx *zedagentContext) (cellularMetrics []*metrics.CellularMetric) {
	m, err := ctx.subWwanMetrics.Get("global")
	if err != nil {
		log.Errorf("subWwanMetrics.Get failed: %v", err)
		return
	}
	wwanMetrics, ok := m.(types.WwanMetrics)
	if !ok {
		log.Errorln("unexpected type of wwan metrics")
		return
	}
	for _, network := range wwanMetrics.Networks {
		if network.LogicalLabel == "" {
			// skip unmanaged modems for now
			continue
		}
		cellularMetrics = append(cellularMetrics,
			&metrics.CellularMetric{
				Logicallabel: network.LogicalLabel,
				SignalStrength: &metrics.CellularSignalStrength{
					Rssi: network.SignalInfo.RSSI,
					Rsrq: network.SignalInfo.RSRQ,
					Rsrp: network.SignalInfo.RSRP,
					Snr:  network.SignalInfo.SNR,
				},
				PacketStats: &metrics.CellularPacketStats{
					Rx: &metrics.NetworkStats{
						TotalPackets: network.PacketStats.RxPackets,
						Drops:        network.PacketStats.RxDrops,
						TotalBytes:   network.PacketStats.RxBytes,
					},
					Tx: &metrics.NetworkStats{
						TotalPackets: network.PacketStats.TxPackets,
						Drops:        network.PacketStats.TxDrops,
						TotalBytes:   network.PacketStats.TxBytes,
					},
				},
			})
	}
	return cellularMetrics
}

func getDiskInfo(ctx *zedagentContext, vrs types.VolumeRefStatus, appDiskDetails *metrics.AppDiskMetric) error {
	appDiskMetric := lookupAppDiskMetric(ctx, vrs.ActiveFileLocation)
	if appDiskMetric == nil {
		return fmt.Errorf("getDiskInfo: No AppDiskMetric found for %s", vrs.ActiveFileLocation)
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
	caCert1, err := os.ReadFile(types.RootCertFileName)
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
	line, err := os.ReadFile(types.V2TLSCertShaFilename)
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
	log.Tracef("getSecurityInfo returns %+v", si)
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
	log.Tracef("encodeProxyStatus: %+v", status)
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
	dp.Cost = uint32(npc.Cost)
	dp.Free = npc.Cost == 0 // To be deprecated
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
	aa *types.AssignableAdapters, iteration int, dest destinationBitset) {
	log.Functionf("PublishAppInfoToZedCloud uuid %s", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	appType := new(info.ZInfoTypes)
	*appType = info.ZInfoTypes_ZiApp
	ReportInfo.Ztype = *appType
	ReportInfo.DevId = *proto.String(devUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportAppInfo := new(info.ZInfoApp)

	ReportAppInfo.AppID = uuid
	ReportAppInfo.SystemApp = false
	if aiStatus != nil {
		ReportAppInfo.AppName = aiStatus.DisplayName
		ReportAppInfo.State = aiStatus.State.ZSwState()
		if !aiStatus.ErrorTime.IsZero() {
			errInfo := encodeErrorInfo(
				aiStatus.ErrorAndTimeWithSource.ErrorDescription)
			ReportAppInfo.AppErr = append(ReportAppInfo.AppErr,
				errInfo)
		}

		if aiStatus.BootTime.IsZero() {
			// If never booted
			log.Functionln("BootTime is empty")
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
					if ib.Type == types.IoNetEthVF {
						reportMac.VfInfo = &info.VfPublishedInfo{Index: uint32(ib.VfParams.Index), VlanId: uint32(ib.VfParams.VlanID)}
					}
					reportAA.IoAddressList = append(reportAA.IoAddressList,
						reportMac)
				}
				log.Tracef("AssignableAdapters for %s macs %v",
					reportAA.Name, reportAA.IoAddressList)
			}
			ReportAppInfo.AssignedAdapters = append(ReportAppInfo.AssignedAdapters,
				reportAA)
		}
		// Get vifs assigned to the application
		// Mostly reporting the UP status
		// We extract the appIP from the dnsmasq assignment
		ifNames := (*aiStatus).GetAppInterfaceList()
		log.Tracef("ReportAppInfo: domainName %s ifs %v",
			aiStatus.DomainName, ifNames)
		for _, ifname := range ifNames {
			networkInfo := new(info.ZInfoNetwork)
			networkInfo.LocalName = *proto.String(ifname)
			ipv4Addr, ipv6Addrs, allocated, macAddr, ipAddrMismatch := getAppIP(ctx, aiStatus,
				ifname)
			networkInfo.IPAddrs = append([]string{ipv4Addr}, ipv6Addrs...)
			networkInfo.MacAddr = *proto.String(macAddr)
			networkInfo.Ipv4Up = allocated
			networkInfo.IpAddrMisMatch = ipAddrMismatch
			name := appIfnameToName(aiStatus, ifname)
			log.Tracef("app %s/%s localName %s devName %s",
				aiStatus.Key(), aiStatus.DisplayName,
				ifname, name)
			networkInfo.DevName = *proto.String(name)
			niStatus := appIfnameToNetworkInstance(ctx, aiStatus, ifname)
			if niStatus != nil {
				networkInfo.NtpServers = []string{}
				if niStatus.NtpServer != nil {
					networkInfo.NtpServers = append(networkInfo.NtpServers, niStatus.NtpServer.String())
				} else {
					ntpServers := types.GetNTPServers(*deviceNetworkStatus,
						niStatus.SelectedUplinkIntf)
					for _, server := range ntpServers {
						networkInfo.NtpServers = append(networkInfo.NtpServers, server.String())
					}
				}

				networkInfo.DefaultRouters = []string{niStatus.Gateway.String()}
				networkInfo.Dns = &info.ZInfoDNS{
					DNSservers: []string{},
				}
				networkInfo.Dns.DNSservers = []string{}
				for _, dnsServer := range niStatus.DnsServers {
					networkInfo.Dns.DNSservers = append(networkInfo.Dns.DNSservers, dnsServer.String())
				}
			}
			ReportAppInfo.Network = append(ReportAppInfo.Network,
				networkInfo)
		}

		for _, vr := range aiStatus.VolumeRefStatusList {
			ReportAppInfo.VolumeRefs = append(ReportAppInfo.VolumeRefs,
				vr.VolumeID.String())
		}
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	log.Functionf("PublishAppInfoToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishAppInfoToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, size, true, false, false,
		info.ZInfoTypes_ZiApp)
}

// PublishContentInfoToZedCloud is called per change, hence needs to try over all management ports
// When content tree Status is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishContentInfoToZedCloud(ctx *zedagentContext, uuid string,
	ctStatus *types.ContentTreeStatus, iteration int, dest destinationBitset) {

	log.Functionf("PublishContentInfoToZedCloud uuid %s", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	contentType := new(info.ZInfoTypes)
	*contentType = info.ZInfoTypes_ZiContentTree
	ReportInfo.Ztype = *contentType
	ReportInfo.DevId = *proto.String(devUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportContentInfo := new(info.ZInfoContentTree)

	ReportContentInfo.Uuid = uuid
	if ctStatus != nil {
		ReportContentInfo.DisplayName = ctStatus.DisplayName
		ReportContentInfo.State = ctStatus.State.ZSwState()
		if !ctStatus.ErrorTime.IsZero() {
			errInfo := encodeErrorInfo(
				ctStatus.ErrorAndTimeWithSource.ErrorDescription)
			ReportContentInfo.Err = errInfo
		}

		ContentResourcesInfo := new(info.ContentResources)
		ContentResourcesInfo.CurSizeBytes = uint64(ctStatus.TotalSize)
		ReportContentInfo.Resources = ContentResourcesInfo
		createTime, _ := ptypes.TimestampProto(ctStatus.CreateTime)
		ReportContentInfo.Usage = &info.UsageInfo{
			// XXX RefCount: uint32(ctStatus.RefCount),
			RefCount:               1,
			LastRefcountChangeTime: createTime,
			CreateTime:             createTime,
		}
		ReportContentInfo.Sha256 = ctStatus.ContentSha256
		ReportContentInfo.ProgressPercentage = uint32(ctStatus.Progress)
		ReportContentInfo.GenerationCount = ctStatus.GenerationCounter
		ReportContentInfo.ComponentShaList = ctStatus.Blobs
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Cinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Cinfo); ok {
		x.Cinfo = ReportContentInfo
	}

	log.Functionf("PublishContentInfoToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishContentInfoToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, size, true, false, false,
		info.ZInfoTypes_ZiContentTree)
}

// PublishVolumeToZedCloud is called per change, hence needs to try over all management ports
// When volume status is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishVolumeToZedCloud(ctx *zedagentContext, uuid string,
	volStatus *types.VolumeStatus, iteration int, dest destinationBitset) {

	log.Functionf("PublishVolumeToZedCloud uuid %s", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	volumeType := new(info.ZInfoTypes)
	*volumeType = info.ZInfoTypes_ZiVolume
	ReportInfo.Ztype = *volumeType
	ReportInfo.DevId = *proto.String(devUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportVolumeInfo := new(info.ZInfoVolume)

	ReportVolumeInfo.Uuid = uuid
	if volStatus != nil {
		ReportVolumeInfo.DisplayName = volStatus.DisplayName
		ReportVolumeInfo.State = volStatus.State.ZSwState()
		if !volStatus.ErrorTime.IsZero() {
			errInfo := encodeErrorInfo(
				volStatus.ErrorAndTimeWithSource.ErrorDescription)
			ReportVolumeInfo.VolumeErr = errInfo
		}

		if volStatus.FileLocation == "" {
			log.Functionf("FileLocation is empty for %s", volStatus.Key())
		} else {
			VolumeResourcesInfo := new(info.VolumeResources)
			err := getVolumeResourcesInfo(ctx, volStatus, VolumeResourcesInfo)
			if err != nil {
				// will be published in handleAppDiskMetricCreate
				log.Functionf("getVolumeResourceInfo(%s) failed %v",
					volStatus.VolumeID, err)
			} else {
				ReportVolumeInfo.Resources = VolumeResourcesInfo
			}
		}
		createTime, _ := ptypes.TimestampProto(volStatus.CreateTime)
		lastChangeTime, _ := ptypes.TimestampProto(volStatus.LastRefCountChangeTime)
		ReportVolumeInfo.Usage = &info.UsageInfo{
			RefCount:               uint32(volStatus.RefCount),
			LastRefcountChangeTime: lastChangeTime,
			CreateTime:             createTime,
		}

		ReportVolumeInfo.ProgressPercentage = uint32(volStatus.Progress)
		ReportVolumeInfo.GenerationCount = volStatus.GenerationCounter
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Vinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Vinfo); ok {
		x.Vinfo = ReportVolumeInfo
	}

	log.Functionf("PublishVolumeToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishVolumeToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, size, true, false, false,
		info.ZInfoTypes_ZiVolume)
}

// PublishBlobInfoToZedCloud is called per change, hence needs to try over all management ports
// When blob Status is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishBlobInfoToZedCloud(ctx *zedagentContext, blobSha string,
	blobStatus *types.BlobStatus, iteration int, dest destinationBitset) {
	log.Functionf("PublishBlobInfoToZedCloud blobSha %v", blobSha)
	var ReportInfo = &info.ZInfoMsg{}

	contentType := new(info.ZInfoTypes)
	*contentType = info.ZInfoTypes_ZiBlobList
	ReportInfo.Ztype = *contentType
	ReportInfo.DevId = *proto.String(devUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportBlobInfoList := new(info.ZInfoBlobList)

	ReportBlobInfo := new(info.ZInfoBlob)

	ReportBlobInfo.Sha256 = blobSha
	if blobStatus != nil {
		ReportBlobInfo.State = blobStatus.State.ZSwState()
		ReportBlobInfo.ProgressPercentage = blobStatus.GetDownloadedPercentage()
		createTime, _ := ptypes.TimestampProto(blobStatus.CreateTime)
		lastChangeTime, _ := ptypes.TimestampProto(blobStatus.LastRefCountChangeTime)
		ReportBlobInfo.Usage = &info.UsageInfo{
			RefCount:               uint32(blobStatus.RefCount),
			LastRefcountChangeTime: lastChangeTime,
			CreateTime:             createTime,
		}
		ReportBlobInfo.Resources = &info.ContentResources{CurSizeBytes: blobStatus.Size}
	}
	ReportBlobInfoList.Blob = append(ReportBlobInfoList.Blob, ReportBlobInfo)

	ReportInfo.InfoContent = new(info.ZInfoMsg_Binfo)
	if blobInfoList, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Binfo); ok {
		blobInfoList.Binfo = ReportBlobInfoList
	}

	log.Functionf("PublishBlobInfoToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishBlobInfoToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, blobSha, buf, size, true, false, false,
		info.ZInfoTypes_ZiBlobList)
}

// PublishEdgeviewToZedCloud - publish Edgeview info to controller
func PublishEdgeviewToZedCloud(ctx *zedagentContext,
	evStatus *types.EdgeviewStatus, dest destinationBitset) {

	log.Functionf("PublishEdgeviewToZedCloud")
	var ReportInfo = &info.ZInfoMsg{}
	bailOnHTTPErr := true
	forcePeriodic := false

	evType := new(info.ZInfoTypes)
	*evType = info.ZInfoTypes_ZiEdgeview
	ReportInfo.Ztype = *evType
	ReportInfo.DevId = *proto.String(devUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportEvInfo := new(info.ZInfoEdgeview)
	if evStatus != nil {
		expTime, _ := ptypes.TimestampProto(time.Unix(int64(evStatus.ExpireOn), 0).UTC())
		startTime, _ := ptypes.TimestampProto(evStatus.StartedOn)
		ReportEvInfo.ExpireTime = expTime
		ReportEvInfo.StartedTime = startTime
		ReportEvInfo.CountDev = evStatus.CmdCountDev
		ReportEvInfo.CountApp = evStatus.CmdCountApp
		ReportEvInfo.CountExt = evStatus.CmdCountExt

		// The first update is important, and that informs zedcloud the edgeivew is 'Active'.
		// Edgeview publish the status when it first connects to dispatcher, which the counters
		// are zeros. Notice that the edgeview container can start/stop at any time, and the
		// counters will be cleared after every start.
		if evStatus.CmdCountDev == 0 && evStatus.CmdCountApp == 0 && evStatus.CmdCountExt == 0 {
			bailOnHTTPErr = false
			forcePeriodic = true
		}
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Evinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Evinfo); ok {
		x.Evinfo = ReportEvInfo
	}

	log.Functionf("PublishEdgeviewToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishEdgeviewToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(ReportInfo))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, "global", buf, size, bailOnHTTPErr, false, forcePeriodic,
		info.ZInfoTypes_ZiEdgeview)
	ctx.iteration++
}

func appIfnameToNetworkInstance(ctx *zedagentContext,
	aiStatus *types.AppInstanceStatus, vifname string) *types.NetworkInstanceStatus {
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.VifUsed == vifname {
			status, _ := ctx.subNetworkInstanceStatus.Get(ulStatus.Network.String())
			if status == nil {
				return nil
			}
			niStatus := status.(types.NetworkInstanceStatus)
			return &niStatus
		}
	}
	return nil
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
	const withNetTrace = false
	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(zedcloudCtx)
	defer cancel()
	rv, err := zedcloud.SendOnAllIntf(ctxWork, zedcloudCtx, url,
		size, buf, iteration, bailOnHTTPErr, withNetTrace)
	if rv.HTTPResp != nil {
		switch rv.HTTPResp.StatusCode {
		// XXX Some controller gives a generic 400 which should be fixed
		case http.StatusBadRequest:
			log.Warnf("XXX SendProtoBuf: %s silently ignore code %d %s",
				url, rv.HTTPResp.StatusCode, http.StatusText(rv.HTTPResp.StatusCode))
			return nil

		case http.StatusNotFound, http.StatusGone:
			// Assume the resource is gone in the controller

			log.Functionf("SendProtoBuf: %s silently ignore code %d %s",
				url, rv.HTTPResp.StatusCode, http.StatusText(rv.HTTPResp.StatusCode))
			return nil
		}
	}
	return err
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func sendMetricsProtobufByURL(ctx *getconfigContext, metricsURL string,
	ReportMetrics *metrics.ZMetricMsg, iteration int) {

	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		log.Fatal("sendMetricsProtobufByURL proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(ReportMetrics))
	const bailOnHTTPErr = false
	const withNetTrace = false
	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(zedcloudCtx)
	defer cancel()
	rv, err := zedcloud.SendOnAllIntf(ctxWork, zedcloudCtx, metricsURL,
		size, buf, iteration, bailOnHTTPErr, withNetTrace)
	if err != nil {
		// Hopefully next timeout will be more successful
		log.Errorf("sendMetricsProtobufByURL status %d failed: %s", rv.Status, err)
		return
	} else {
		maybeUpdateMetricsTimer(ctx, true)
		saveSentMetricsProtoMessage(data)
	}
}

func sendMetricsProtobuf(ctx *getconfigContext,
	ReportMetrics *metrics.ZMetricMsg, iteration int) {

	url := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "metrics")
	sendMetricsProtobufByURL(ctx, url, ReportMetrics, iteration)

	locConfig := ctx.locConfig

	// Repeat metrics for LOC as well
	if locConfig != nil {
		// Don't block current execution context
		go func() {
			url := zedcloud.URLPathString(locConfig.LocURL, zedcloudCtx.V2API,
				devUUID, "metrics")
			sendMetricsProtobufByURL(ctx, url, ReportMetrics, iteration)
		}()
	}
}

// Use the ifname/vifname to find the underlay status
// and from there the (ip, allocated, mac) addresses for the app
func getAppIP(ctx *zedagentContext, aiStatus *types.AppInstanceStatus,
	vifname string) (string, []string, bool, string, bool) {

	log.Tracef("getAppIP(%s, %s)", aiStatus.Key(), vifname)
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.VifUsed != vifname {
			continue
		}
		log.Tracef("getAppIP(%s, %s) found underlay v4: %s, v6: %s, ipv4 assigned %v mac %s",
			aiStatus.Key(), vifname, ulStatus.AllocatedIPv4Addr,
			ulStatus.AllocatedIPv6List, ulStatus.IPv4Assigned, ulStatus.Mac)
		return ulStatus.AllocatedIPv4Addr, ulStatus.AllocatedIPv6List, ulStatus.IPv4Assigned, ulStatus.Mac, ulStatus.IPAddrMisMatch
	}
	return "", []string{}, false, "", false
}

func createVolumeInstanceMetrics(ctx *zedagentContext, reportMetrics *metrics.ZMetricMsg) {
	log.Tracef("Volume instance metrics started")
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
			log.Functionf("FileLocation is empty for %s", volumeStatus.Key())
		} else {
			getVolumeResourcesMetrics(ctx, volumeStatus.FileLocation, volumeMetric)
		}
		reportMetrics.Vm = append(reportMetrics.Vm, volumeMetric)
	}
	log.Tracef("Volume instance metrics done: %v", reportMetrics.Vm)
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

func createProcessMetrics(ctx *zedagentContext, reportMetrics *metrics.ZMetricMsg) {
	log.Tracef("Process metrics started")
	sub := ctx.getconfigCtx.subProcessMetric
	items := sub.GetAll()
	for _, item := range items {
		p := item.(types.ProcessMetric)
		processMetric := new(metrics.ZMetricProcess)
		processMetric.Pid = p.Pid
		processMetric.Name = p.Name
		processMetric.UserProcess = p.UserProcess
		processMetric.Watched = p.Watched
		processMetric.NumFds = p.NumFDs
		processMetric.NumThreads = p.NumThreads
		processMetric.UserTime = p.UserTime
		processMetric.SystemTime = p.SystemTime
		processMetric.CpuPercent = p.CPUPercent
		protoTime, err := ptypes.TimestampProto(p.CreateTime)
		if err == nil {
			processMetric.CreateTime = protoTime
		}
		processMetric.VmBytes = p.VMBytes
		processMetric.RssBytes = p.RssBytes
		processMetric.MemoryPercent = p.MemoryPercent
		// XXX block sending stacks to reduce the size of metrics message, for now.
		//processMetric.Stack = p.Stack
		reportMetrics.Pr = append(reportMetrics.Pr, processMetric)
	}
	log.Tracef("Process metrics done: %v", reportMetrics.Pr)
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
	log.Traceln("network instance metrics: ", reportMetrics.Nm)
}

func protoEncodeNetworkInstanceMetricProto(status types.NetworkInstanceMetrics) *zmet.ZMetricNetworkInstance {

	metric := new(zmet.ZMetricNetworkInstance)
	metric.NetworkID = status.Key()
	metric.NetworkVersion = status.UUIDandVersion.Version
	metric.Displayname = status.DisplayName
	metric.InstType = uint32(status.Type)
	vlanInfo := new(zmet.VlanInfo)
	vlanInfo.NumTrunkPorts = status.VlanMetrics.NumTrunkPorts
	vlanInfo.VlanCounts = status.VlanMetrics.VlanCounts
	protoEncodeGenericInstanceMetric(status, metric)
	metric.ProbeMetric = protoEncodeProbeMetrics(status.ProbeMetrics)
	return metric
}

func protoEncodeProbeMetrics(probeMetrics types.ProbeMetrics) *metrics.ZProbeNIMetrics {
	protoMetrics := &metrics.ZProbeNIMetrics{
		CurrentIntf:    probeMetrics.SelectedUplinkIntf,
		RemoteEndpoint: strings.Join(probeMetrics.RemoteEndpoints, ", "),
		PingIntv:       probeMetrics.LocalPingIntvl,
		RemotePingIntv: probeMetrics.RemotePingIntvl,
		UplinkCnt:      probeMetrics.UplinkCount,
	}
	for _, intfStats := range probeMetrics.IntfProbeStats {
		var nextHops []string
		for _, nh := range intfStats.NexthopIPs {
			nextHops = append(nextHops, nh.String())
		}
		protoMetrics.IntfMetric = append(protoMetrics.IntfMetric,
			&metrics.ZProbeNIMetrics_ZProbeIntfMetric{
				IntfName:           intfStats.IntfName,
				GatewayNexhtop:     strings.Join(nextHops, ", "),
				GatewayUP:          intfStats.NexthopUP,
				RemoteHostUP:       intfStats.RemoteUP,
				NexthopUpCount:     intfStats.NexthopUPCnt,
				NexthopDownCount:   intfStats.NexthopDownCnt,
				RemoteUpCount:      intfStats.RemoteUPCnt,
				RemoteDownCount:    intfStats.RemoteDownCnt,
				RemoteProbeLatency: intfStats.LatencyToRemote,
			})
	}
	return protoMetrics
}

func protoEncodeFlowlogCounters(counters types.FlowlogCounters) *metrics.FlowlogCounters {
	return &metrics.FlowlogCounters{
		Success:        counters.Success,
		Drops:          counters.Drops,
		FailedAttempts: counters.FailedAttempts,
	}
}

// getDormantTime returns scaled dormant time
func getDormantTime(ctx *zedagentContext) uint64 {
	return uint64(ctx.globalConfig.GlobalValueInt(types.MetricInterval) * dormantTimeScaleFactor)
}

func fillStorageVDevMetrics(obj *types.ZFSVDevMetrics) *zmet.StorageVDevMetrics {
	storageVDevMetrics := new(metrics.StorageVDevMetrics)
	storageVDevMetrics.Alloc = *proto.Uint64(obj.Alloc)
	storageVDevMetrics.Total = *proto.Uint64(obj.Space)
	storageVDevMetrics.DeflatedSpace = *proto.Uint64(obj.DSpace)
	storageVDevMetrics.ReplaceableSize = *proto.Uint64(obj.RSize)
	storageVDevMetrics.ExpandableSize = *proto.Uint64(obj.ESize)
	storageVDevMetrics.ReadErrors = *proto.Uint64(obj.ReadErrors)
	storageVDevMetrics.WriteErrors = *proto.Uint64(obj.WriteErrors)
	storageVDevMetrics.ChecksumErrors = *proto.Uint64(obj.ChecksumErrors)
	storageVDevMetrics.BytesRead = *proto.Uint64(obj.Bytes[types.ZIOTypeRead])
	storageVDevMetrics.BytesWrite = *proto.Uint64(obj.Bytes[types.ZIOTypeWrite])
	storageVDevMetrics.OpsCountRead = *proto.Uint64(obj.Ops[types.ZIOTypeRead])
	storageVDevMetrics.OpsCountWrite = *proto.Uint64(obj.Ops[types.ZIOTypeWrite])
	storageVDevMetrics.IOsInProgress = *proto.Uint64(obj.IOsInProgress)
	storageVDevMetrics.ReadTicks = *proto.Uint64(obj.ReadTicks)
	storageVDevMetrics.WriteTicks = *proto.Uint64(obj.WriteTicks)
	storageVDevMetrics.IOsTotalTicks = *proto.Uint64(obj.IOsTotalTicks)
	storageVDevMetrics.WeightedIOTicks = *proto.Uint64(obj.WeightedIOTicks)
	return storageVDevMetrics
}

func fillStorageZVolMetrics(zvol *types.StorageZVolMetrics) *metrics.StorageVDevMetrics {
	zvolMetrics := new(metrics.StorageVDevMetrics)
	zvolMetrics.VolumeUUID = *proto.String(zvol.VolumeID.String())
	zvolMetrics.BytesRead = *proto.Uint64(zvol.Metrics.Bytes[types.ZIOTypeRead])
	zvolMetrics.BytesWrite = *proto.Uint64(zvol.Metrics.Bytes[types.ZIOTypeWrite])
	zvolMetrics.OpsCountRead = *proto.Uint64(zvol.Metrics.Ops[types.ZIOTypeRead])
	zvolMetrics.OpsCountWrite = *proto.Uint64(zvol.Metrics.Ops[types.ZIOTypeWrite])
	zvolMetrics.IOsInProgress = *proto.Uint64(zvol.Metrics.IOsInProgress)
	zvolMetrics.ReadTicks = *proto.Uint64(zvol.Metrics.ReadTicks)
	zvolMetrics.WriteTicks = *proto.Uint64(zvol.Metrics.WriteTicks)
	zvolMetrics.IOsTotalTicks = *proto.Uint64(zvol.Metrics.IOsTotalTicks)
	zvolMetrics.WeightedIOTicks = *proto.Uint64(zvol.Metrics.WeightedIOTicks)
	return zvolMetrics
}

func fillStorageDiskMetrics(disk *types.StorageDiskMetrics) *metrics.StorageDiskMetric {
	diskMetric := new(metrics.StorageDiskMetric)

	if disk.DiskName != nil {
		diskMetric.DiskName = new(evecommon.DiskDescription)
		diskMetric.DiskName.Name = *proto.String(disk.DiskName.Name)
		diskMetric.DiskName.LogicalName = *proto.String(disk.DiskName.LogicalName)
		diskMetric.DiskName.Serial = *proto.String(disk.DiskName.Serial)
	}
	if disk.Metrics != nil {
		diskMetric.Metrics = fillStorageVDevMetrics(disk.Metrics)
	}
	return diskMetric
}

func fillStorageChildrenMetrics(childrenDataset *types.StorageChildrenMetrics) *metrics.StorageChildrenMetric {
	storageChildren := new(metrics.StorageChildrenMetric)
	storageChildren.GUID = *proto.Uint64(childrenDataset.GUID)
	storageChildren.Metrics = fillStorageVDevMetrics(childrenDataset.Metrics)

	for _, child := range childrenDataset.Children {
		storageChildren.Children = append(storageChildren.Children,
			fillStorageChildrenMetrics(child))
	}

	for _, disk := range childrenDataset.Disks {
		storageChildren.Disks = append(storageChildren.Disks,
			fillStorageDiskMetrics(disk))
	}
	return storageChildren
}

func fillStorageMetrics(zpoolMetrics *types.ZFSPoolMetrics) *metrics.StorageMetric {
	storageMetrics := new(metrics.StorageMetric)
	storageMetrics.PoolName = *proto.String(zpoolMetrics.PoolName)
	tmpCollectionTime, err := ptypes.TimestampProto(zpoolMetrics.CollectionTime)
	if err != nil {
		log.Errorf("fillStorageMetrics: failed to convert CollectionTime %v", err)
	}
	storageMetrics.CollectionTime = tmpCollectionTime
	storageMetrics.ZpoolMetrics = fillStorageVDevMetrics(zpoolMetrics.Metrics)

	// Fill metrics for RAID or Mirror
	for _, child := range zpoolMetrics.ChildrenDataset {
		storageMetrics.ChildrenDatasets = append(storageMetrics.ChildrenDatasets,
			fillStorageChildrenMetrics(child))
	}

	// Fill metrics for disks that are not included in the RAID or mirror
	for _, disk := range zpoolMetrics.Disks {
		storageMetrics.Disks = append(storageMetrics.Disks,
			fillStorageDiskMetrics(disk))
	}

	// Fill metrics for zvols
	for _, zvol := range zpoolMetrics.ZVols {
		storageMetrics.Zvols = append(storageMetrics.Zvols,
			fillStorageZVolMetrics(zvol))
	}

	return storageMetrics
}
