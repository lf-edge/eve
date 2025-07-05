// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Push metrics to controller

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/hardwarehealth"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/metrics"
	zmet "github.com/lf-edge/eve-api/go/metrics" // zinfo and zmet here
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"github.com/multiplay/go-edac/lib/edac"
	"github.com/shirou/gopsutil/host"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	path := status.DiskPath
	log.Functionf("handleDiskMetricImpl: %s", path)
}

func handleDiskMetricDelete(ctxArg interface{}, key string, statusArg interface{}) {
	status := statusArg.(types.DiskMetric)
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
	errInfo.Timestamp = timestamppb.New(et.ErrorTime)
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
		errInfo.Severity = info.Severity_SEVERITY_ERROR
	} else {
		timestamp = tr.LastSucceeded
		if tr.HasWarning() {
			errInfo.Description = tr.LastWarning
			errInfo.Severity = info.Severity_SEVERITY_WARNING
		}
	}
	if !timestamp.IsZero() {
		errInfo.Timestamp = timestamppb.New(timestamp)
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

			locConfig := ctx.getconfigCtx.sideController.locConfig
			if locConfig != nil {
				// Publish all info by timer only for LOC. LOC is
				// always special due its volatile nature, so set
				// @ForceSend to be sure request will be send
				// regardless of any checks applied to a request
				// (check handlentp.go for details).
				triggerPublishAllInfo(ctx, LOCDest|ForceSend)
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
	ReportMetrics.AtTimeStamp = timestamppb.Now()

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
	ReportDeviceMetric.CpuMetric.UpTime = timestamppb.New(
		time.Unix(int64(info.Uptime), 0).UTC())

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
	for _, p := range deviceNetworkStatus.Ports {
		var metric *types.NetworkMetric
		if p.IfName == "" {
			// Cannot associate metrics with the port until interface name is known.
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
		networkDetails.IName = p.Logicallabel
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
	ctx.agentMetrics.AddInto(log, cms)
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
			metric.LastFailure = timestamppb.New(cm.LastFailure)
		}
		if !cm.LastSuccess.IsZero() {
			metric.LastSuccess = timestamppb.New(cm.LastSuccess)
		}
		for url, um := range cm.URLCounters {
			log.Tracef("ControllerConnMetrics[%s] url %s %v",
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
		TotalSizeLogs:       newlogMetrics.TotalSizeLogs,
	}
	if !newlogMetrics.FailSentStartTime.IsZero() {
		nlm.FailSentStartTime = timestamppb.New(newlogMetrics.FailSentStartTime)
	}
	if !newlogMetrics.OldestSavedDeviceLog.IsZero() {
		nlm.OldestSavedDeviceLog = timestamppb.New(newlogMetrics.OldestSavedDeviceLog)
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
		devM.RecentGzipFileTime = timestamppb.New(newlogMetrics.DevMetrics.RecentUploadTimestamp)
	}
	if !newlogMetrics.DevMetrics.LastGZipFileSendTime.IsZero() {
		devM.LastGzipFileSendTime = timestamppb.New(newlogMetrics.DevMetrics.LastGZipFileSendTime)
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
		appM.RecentGzipFileTime = timestamppb.New(newlogMetrics.AppMetrics.RecentUploadTimestamp)
	}
	if !newlogMetrics.AppMetrics.LastGZipFileSendTime.IsZero() {
		appM.LastGzipFileSendTime = timestamppb.New(newlogMetrics.AppMetrics.LastGZipFileSendTime)
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
		cipherMetricsWwan,
	}
	for _, cm := range cipherMetrics {
		log.Functionf("Cipher metrics for %s: %+v", cm.AgentName, cm)
		metric := metrics.CipherMetric{AgentName: cm.AgentName,
			FailureCount: cm.FailureCount,
			SuccessCount: cm.SuccessCount,
		}
		if !cm.LastFailure.IsZero() {
			metric.LastFailure = timestamppb.New(cm.LastFailure)
		}
		if !cm.LastSuccess.IsZero() {
			metric.LastSuccess = timestamppb.New(cm.LastSuccess)
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
			ReportMetrics.AtTimeStamp = timestamppb.New(dm.LastHeard)
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
		ReportDeviceMetric.LastReceivedConfig = timestamppb.New(ctx.getconfigCtx.lastReceivedConfig)
	}
	if !ctx.getconfigCtx.lastProcessedConfig.IsZero() {
		ReportDeviceMetric.LastProcessedConfig = timestamppb.New(ctx.getconfigCtx.lastProcessedConfig)
	}
	ReportDeviceMetric.DormantTimeInSeconds = getDormantTime(ctx)

	// Report metrics from ZFS
	if persist.ReadPersistType() == types.PersistZFS {
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

		// In cluster mode, if ENClusterAppStatus reports the app is not scheduled on the node,
		// to avoid publishing the stats to controller by multiple nodes, zedmanager set this flag
		// and zedagent will not publish the stats to controller for this App.
		if aiStatus.NoUploadStatsToController {
			log.Tracef("ReportMetrics: domainName %s, not upload metrics, NoUploadStatsToController set",
				aiStatus.DomainName)
			continue
		}
		ReportAppMetric := new(metrics.AppMetric)
		ReportAppMetric.Cpu = new(metrics.AppCpuMetric)
		// New AppMemoryMetric
		ReportAppMetric.AppMemory = new(metrics.AppMemoryMetric)
		// MemoryMetric is deprecated; keep for old controllers for now
		ReportAppMetric.Memory = new(metrics.MemoryMetric)
		ReportAppMetric.AppName = aiStatus.DisplayName
		ReportAppMetric.AppID = aiStatus.Key()
		ReportAppMetric.PatchEnvelope = composePatchEnvelopeUsage(aiStatus.Key(), ctx)

		if !aiStatus.BootTime.IsZero() && aiStatus.Activated {
			elapsed := time.Since(aiStatus.BootTime)
			ReportAppMetric.Cpu.UpTime = timestamppb.New(
				time.Unix(0, elapsed.Nanoseconds()).UTC())
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
					appContainerMetric.Cpu.UpTime = timestamppb.New(time.Unix(0, stats.Uptime).UTC())
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
	if ctx.agentMetrics != nil {
		ctx.agentMetrics.Publish(log, ctx.pubMetricsMap, "global")
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

// hardwareHealthTimerTask periodically publishes hardware health check reports.
// It starts by attempting an initial health check report. If the initial attempt fails,
// it uses a short retry interval; otherwise, it uses a configurable interval from globalConfig.
//
// The function runs indefinitely until the process is stopped or the context is canceled.
func hardwareHealthTimerTask(ctx *zedagentContext, handleChannel chan interface{}) {
	iteration := 0
	log.Functionln("starting report health check timer task")
	success := publishΗealthChecksReport(ctx, iteration)
	retry := !success

	// Run a timer for extra safety to send hardwarehealth updates
	// If we failed with the initial we have a short timer, otherwise
	// the configurable one.
	const shortTimeSecs = 120 // Short time: two minutes
	hardwareHealthInterval := ctx.globalConfig.GlobalValueInt(types.HardwareHealthInterval)
	interval := time.Duration(hardwareHealthInterval)
	if retry {
		log.Noticef("Initial publishHardwareHealth failed; switching to short timer")
		interval = shortTimeSecs
	}
	max := float64(interval * time.Second)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	wdName := agentName + "hardwarehealth"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			iteration++
			success = publishΗealthChecksReport(ctx, iteration) // update success status
			ctx.ps.CheckMaxTimeTopic(wdName, "publishHardwareHealth", start,
				warningTime, errorTime)

			if retry && success {
				log.Noticef("Publishing hardwarehealth succeeded; switching to long timer %d seconds",
					hardwareHealthInterval)
				updateTaskTimer(hardwareHealthInterval, ticker)
				retry = false
			} else if !retry && !success {
				log.Noticef("Hardwarehealth failed; switching to short timer")
				updateTaskTimer(shortTimeSecs, ticker)
				retry = true
			}
		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// publishΗealthChecksReport collects hardware health metrics, currently only for ECC memory
// and publishes a health report to the controller. If ECC memory controllers are not present
// or an error occurs during collection, an empty report is sent to indicate the inability to
// gather the information.
//
// Returns:
//
//	bool - The result of the sendHardwareHealthProtobuf operation.
func publishΗealthChecksReport(ctx *zedagentContext, iteration int) bool {
	log.Functionf("publishΗealthChecksReport")
	var ReportHardwareHealth = &hardwarehealth.ZHardwareHealth{}

	ReportHardwareHealth.DevId = *proto.String(devUUID.String())
	ReportHardwareHealth.AtTimeStamp = timestamppb.Now()

	ReportMemoryInfo := new(hardwarehealth.ECCMemoryReport)

	mcs, err := edac.MemoryControllers()
	if err != nil {
		log.Error(err)
	}

	for _, c := range mcs {
		i, err := c.Info()
		if err != nil {
			log.Error(err)
			continue
		}

		// Add ECC memory controller info
		memoryInfo := &hardwarehealth.ECCMemoryControllerInfo{
			ControllerName: i.Name,
			CeCount:        i.Correctable,
			UeCount:        i.Uncorrectable,
		}

		// Retrieve and add DIMM ranks
		ranks, err := c.DimmRanks()
		if err != nil {
			log.Error(err)
			continue
		}

		for _, r := range ranks {
			dimmRank := &hardwarehealth.DimmRankInfo{
				RankName: r.Name,
				CeCount:  r.Correctable,
				UeCount:  r.Uncorrectable,
			}
			memoryInfo.Ranks = append(memoryInfo.Ranks, dimmRank)
		}

		ReportMemoryInfo.MemoryControllers = append(ReportMemoryInfo.MemoryControllers, memoryInfo)
	}
	ReportHardwareHealth.Mr = ReportMemoryInfo

	log.Tracef("PublishHardwareHealthToZedCloud sending %s", ReportHardwareHealth)
	return sendHardwareHealthProtobuf(ctx.getconfigCtx, ReportHardwareHealth, iteration)
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
	ReportInfo.AtTimeStamp = timestamppb.Now()

	ReportAppInfo := new(info.ZInfoApp)

	ReportAppInfo.AppID = uuid
	ReportAppInfo.SystemApp = false
	ReportAppInfo.ClusterAppRunning = false

	if aiStatus != nil {
		// In cluster mode, if ENClusterAppStatus reports the app is not scheduled on the node,
		// to avoid publishing the stats to controller by multiple nodes, zedmanager set this flag
		// and zedagent will not publish the stats to controller for this App.
		if aiStatus.NoUploadStatsToController {
			log.Tracef("PublishAppInfoToZedCloud: domainName %s, not upload info, NoUploadStatsToController set", aiStatus.DomainName)
			return
		}

		ReportAppInfo.AppVersion = aiStatus.UUIDandVersion.Version
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
			ReportAppInfo.BootTime = timestamppb.New(aiStatus.BootTime)
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
			addrs, hasIPv4Addr, macAddr, ipAddrMismatch :=
				getAppIPs(ctx, aiStatus, ifname)
			for _, ipv4Addr := range addrs.IPv4Addrs {
				networkInfo.IPAddrs = append(networkInfo.IPAddrs,
					ipv4Addr.Address.String())
			}
			for _, ipv6Addr := range addrs.IPv6Addrs {
				networkInfo.IPAddrs = append(networkInfo.IPAddrs,
					ipv6Addr.Address.String())
			}
			networkInfo.MacAddr = *proto.String(macAddr.String())
			networkInfo.Ipv4Up = hasIPv4Addr
			networkInfo.IpAddrMisMatch = ipAddrMismatch
			name := appIfnameToName(aiStatus, ifname)
			log.Tracef("app %s/%s localName %s devName %s",
				aiStatus.Key(), aiStatus.DisplayName,
				ifname, name)
			networkInfo.DevName = *proto.String(name)
			niStatus := appIfnameToNetworkInstance(ctx, aiStatus, ifname)
			if niStatus != nil {
				networkInfo.NtpServers = append(networkInfo.NtpServers, niStatus.NTPServers...)
				networkInfo.DefaultRouters = []string{niStatus.Gateway.String()}
				networkInfo.Dns = &info.ZInfoDNS{
					DNSservers: []string{},
				}
				networkInfo.Dns.DNSservers = []string{}
				for _, dnsServer := range niStatus.DnsServers {
					networkInfo.Dns.DNSservers = append(networkInfo.Dns.DNSservers,
						dnsServer.String())
				}
			}
			ReportAppInfo.Network = append(ReportAppInfo.Network,
				networkInfo)
		}

		for _, vr := range aiStatus.VolumeRefStatusList {
			ReportAppInfo.VolumeRefs = append(ReportAppInfo.VolumeRefs,
				vr.VolumeID.String())
		}

		for _, snap := range aiStatus.SnapStatus.AvailableSnapshots {
			snapInfo := new(info.ZInfoSnapshot)
			snapInfo.Id = snap.Snapshot.SnapshotID
			snapInfo.ConfigId = snap.ConfigVersion.UUID.String()
			snapInfo.ConfigVersion = snap.ConfigVersion.Version
			snapInfo.CreateTime = timestamppb.New(snap.TimeCreated)
			snapInfo.Type = snap.Snapshot.SnapshotType.ConvertToInfoSnapshotType()
			snapInfo.SnapErr = encodeErrorInfo(snap.Error)
			ReportAppInfo.Snapshots = append(ReportAppInfo.Snapshots, snapInfo)
		}

		// For Clustered apps on HV=kubevirt, 'ClusterAppRunning' designates
		// the app is running on this node either naturally or after some failover event.
		ReportAppInfo.ClusterAppRunning = aiStatus.Activated
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

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, true, false, false,
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
	ReportInfo.AtTimeStamp = timestamppb.Now()

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
		ReportContentInfo.Usage = &info.UsageInfo{
			// XXX RefCount: uint32(ctStatus.RefCount),
			RefCount:               1,
			LastRefcountChangeTime: timestamppb.New(ctStatus.CreateTime),
			CreateTime:             timestamppb.New(ctStatus.CreateTime),
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

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, true, false, false,
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
	ReportInfo.AtTimeStamp = timestamppb.Now()

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
		ReportVolumeInfo.Usage = &info.UsageInfo{
			RefCount:               uint32(volStatus.RefCount),
			LastRefcountChangeTime: timestamppb.New(volStatus.LastRefCountChangeTime),
			CreateTime:             timestamppb.New(volStatus.CreateTime),
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

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, uuid, buf, true, false, false,
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
	ReportInfo.AtTimeStamp = timestamppb.Now()

	ReportBlobInfoList := new(info.ZInfoBlobList)

	ReportBlobInfo := new(info.ZInfoBlob)

	ReportBlobInfo.Sha256 = blobSha
	if blobStatus != nil {
		ReportBlobInfo.State = blobStatus.State.ZSwState()
		ReportBlobInfo.ProgressPercentage = blobStatus.GetDownloadedPercentage()
		ReportBlobInfo.Usage = &info.UsageInfo{
			RefCount:               uint32(blobStatus.RefCount),
			LastRefcountChangeTime: timestamppb.New(blobStatus.LastRefCountChangeTime),
			CreateTime:             timestamppb.New(blobStatus.CreateTime),
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

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, blobSha, buf, true, false, false,
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
	ReportInfo.AtTimeStamp = timestamppb.Now()

	ReportEvInfo := new(info.ZInfoEdgeview)
	if evStatus != nil {
		ReportEvInfo.ExpireTime = timestamppb.New(time.Unix(int64(evStatus.ExpireOn), 0).UTC())
		ReportEvInfo.StartedTime = timestamppb.New(evStatus.StartedOn)
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

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, "global", buf, bailOnHTTPErr, false, forcePeriodic,
		info.ZInfoTypes_ZiEdgeview)
}

func appIfnameToNetworkInstance(ctx *zedagentContext,
	aiStatus *types.AppInstanceStatus, vifname string) *types.NetworkInstanceStatus {
	for _, adapterStatus := range aiStatus.AppNetAdapters {
		if adapterStatus.VifUsed == vifname {
			status, _ := ctx.subNetworkInstanceStatus.Get(adapterStatus.Network.String())
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
	for _, adapterStatus := range aiStatus.AppNetAdapters {
		if adapterStatus.VifUsed == vifname {
			return adapterStatus.Name
		}
	}
	return ""
}

// This function is called per change, hence needs to try over all management ports
// For each port we try different source IPs until we find a working one.
// For the HTTP errors indicating the object is gone we ignore the error
// so the caller does not defer and retry
func SendProtobuf(url string, buf *bytes.Buffer, iteration int) error {
	ctxWork, cancel := ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	rv, err := ctrlClient.SendOnAllIntf(ctxWork, url, buf, controllerconn.RequestOptions{
		WithNetTracing: false,
		// For 4xx and 5xx HTTP errors we don't try other interfaces
		BailOnHTTPErr: true,
		Iteration:     iteration,
	})
	if rv.HTTPResp != nil {
		switch rv.HTTPResp.StatusCode {
		// XXX Some controller gives a generic 400 which should be fixed
		case http.StatusBadRequest:
			log.Warnf("SendProtoBuf: Ignoring bad request for %s - code %d %s (controller issue should be fixed)",
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
	ReportMetrics *metrics.ZMetricMsg, iteration int, expectNoConn bool) {

	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		log.Fatal("sendMetricsProtobufByURL proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	ctxWork, cancel := ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	rv, err := ctrlClient.SendOnAllIntf(ctxWork, metricsURL, buf,
		controllerconn.RequestOptions{
			WithNetTracing: false,
			BailOnHTTPErr:  false,
			Iteration:      iteration,
			SuppressLogs:   expectNoConn,
		})
	if err != nil {
		// Hopefully next timeout will be more successful
		if !expectNoConn {
			log.Errorf("sendMetricsProtobufByURL status %d failed: %s", rv.Status, err)
		}
		return
	} else {
		maybeUpdateMetricsTimer(ctx, true)
		saveSentMetricsProtoMessage(data)
	}
}

func sendMetricsProtobuf(ctx *getconfigContext,
	ReportMetrics *metrics.ZMetricMsg, iteration int) {

	url := controllerconn.URLPathString(serverNameAndPort, ctrlClient.UsingV2API(),
		devUUID, "metrics")
	sendMetricsProtobufByURL(ctx, url, ReportMetrics, iteration, ctx.zedagentCtx.airgapMode)

	locConfig := ctx.sideController.locConfig

	// Repeat metrics for LOC as well
	if locConfig != nil {
		// Don't block current execution context
		go func() {
			url := controllerconn.URLPathString(locConfig.LocURL, ctrlClient.UsingV2API(),
				devUUID, "metrics")
			sendMetricsProtobufByURL(ctx, url, ReportMetrics, iteration, false)
		}()
	}
}

// sendHardwareHealthProtobufByURL serializes the provided ZHardwareHealth protobuf message and sends it
// to the specified hardware health URL using the zedcloud transport layer. The function attempts to send
// the message on all available network interfaces, handling marshaling errors and HTTP transmission errors.
// On successful transmission, the sent message is saved for record-keeping.
//
// Returns:
//   - bool: true if the message was sent successfully, false otherwise.
func sendHardwareHealthProtobufByURL(ctx *getconfigContext, hardwareHealthURL string,
	HardwareHealth *hardwarehealth.ZHardwareHealth, iteration int, expectNoConn bool) bool {

	data, err := proto.Marshal(HardwareHealth)
	if err != nil {
		log.Fatal("sendHardwareHealthProtobufByURL proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	ctxWork, cancel := ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	if !expectNoConn {
		log.Noticef("sending hardware health message: %s", hardwareHealthURL)
	}
	rv, err := ctrlClient.SendOnAllIntf(ctxWork, hardwareHealthURL, buf,
		controllerconn.RequestOptions{
			WithNetTracing: false,
			BailOnHTTPErr:  false,
			Iteration:      iteration,
			SuppressLogs:   expectNoConn,
		})
	if err != nil {
		// Hopefully next timeout will be more successful
		if !expectNoConn {
			log.Errorf("sendHardwareHealthProtobufByURL status %d failed: %s",
				rv.Status, err)
		}
		return false
	} else {
		saveSentHardwareHealthProtoMessage(data)
	}
	return true
}

// sendHardwareHealthProtobuf serializes and sends the provided hardware health protobuf message
// to the controller, and if a local controller configuration is present, also sends it asynchronously
// to the local controller.
//
// Returns:
//   - bool: true if the message was sent successfully to the primary controller, false otherwise.
func sendHardwareHealthProtobuf(ctx *getconfigContext,
	HardwareHealth *hardwarehealth.ZHardwareHealth, iteration int) bool {

	url := controllerconn.URLPathString(serverNameAndPort, ctrlClient.UsingV2API(),
		devUUID, "hardwarehealth")
	ret := sendHardwareHealthProtobufByURL(ctx, url, HardwareHealth, iteration,
		ctx.zedagentCtx.airgapMode)

	locConfig := ctx.sideController.locConfig

	// Repeat hardwarehealth for LOC as well
	if locConfig != nil {
		// Don't block current execution context
		go func() {
			url := controllerconn.URLPathString(locConfig.LocURL, ctrlClient.UsingV2API(),
				devUUID, "hardwarehealth")
			sendHardwareHealthProtobufByURL(ctx, url, HardwareHealth, iteration, false)
		}()
	}
	return ret
}

// Use the ifname/vifname to find the AppNetAdapter status
// and from there the (ip, allocated, mac) addresses for the app
func getAppIPs(ctx *zedagentContext, aiStatus *types.AppInstanceStatus,
	vifname string) (types.AssignedAddrs, bool, net.HardwareAddr, bool) {

	log.Tracef("getAppIP(%s, %s)", aiStatus.Key(), vifname)
	for _, adapterStatus := range aiStatus.AppNetAdapters {
		if adapterStatus.VifUsed != vifname {
			continue
		}
		log.Tracef("getAppIP(%s, %s) found AppIPs v4: %v, v6: %v, ipv4 assigned %v mac %s",
			aiStatus.Key(), vifname, adapterStatus.AssignedAddresses.IPv4Addrs,
			adapterStatus.AssignedAddresses.IPv6Addrs, adapterStatus.IPv4Assigned,
			adapterStatus.Mac)
		return adapterStatus.AssignedAddresses, adapterStatus.IPv4Assigned,
			adapterStatus.Mac, adapterStatus.IPAddrMisMatch
	}
	return types.AssignedAddrs{}, false, nil, false
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
		processMetric.CreateTime = timestamppb.New(p.CreateTime)
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
	for _, pm := range status.ProbeMetrics {
		metric.ProbeMetrics = append(metric.ProbeMetrics, protoEncodeProbeMetrics(pm))
	}
	return metric
}

func protoEncodeProbeMetrics(probeMetrics types.ProbeMetrics) *metrics.ZProbeNIMetrics {
	protoMetrics := &metrics.ZProbeNIMetrics{
		DstNetwork:     probeMetrics.DstNetwork,
		CurrentPort:    probeMetrics.SelectedPort,
		CurrentIntf:    probeMetrics.SelectedPortIfName,
		RemoteEndpoint: strings.Join(probeMetrics.RemoteEndpoints, ", "),
		PingIntv:       probeMetrics.LocalPingIntvl,
		RemotePingIntv: probeMetrics.RemotePingIntvl,
		UplinkCnt:      probeMetrics.PortCount,
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
	storageMetrics.CollectionTime = timestamppb.New(zpoolMetrics.CollectionTime)
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
