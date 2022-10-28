/*
 * Copyright (c) 2020. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package volumemgr

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
	"github.com/shirou/gopsutil/disk"
)

func publishDiskMetrics(ctx *volumemgrContext, statuses ...*types.DiskMetric) {
	for _, status := range statuses {
		key := status.Key()
		log.Tracef("publishDiskMetrics(%s)", key)
		pub := ctx.pubDiskMetric
		pub.Publish(key, *status)
		log.Tracef("publishDiskMetrics(%s) Done", key)
	}
}

func unpublishDiskMetrics(ctx *volumemgrContext, statuses ...*types.DiskMetric) {
	for _, status := range statuses {
		key := status.Key()
		log.Tracef("unpublishDiskMetrics(%s)", key)
		pub := ctx.pubDiskMetric
		c, _ := pub.Get(key)
		if c == nil {
			log.Errorf("unpublishDiskMetrics(%s) not found", key)
			continue
		}
		pub.Unpublish(key)
		log.Tracef("unpublishDiskMetrics(%s) Done", key)
	}
}

func lookupDiskMetric(ctx *volumemgrContext, key string) *types.DiskMetric {
	key = types.PathToKey(key)
	log.Tracef("lookupDiskMetric(%s)", key)
	pub := ctx.pubDiskMetric
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupDiskMetric(%s) not found", key)
		return nil
	}
	status := c.(types.DiskMetric)
	log.Tracef("lookupDiskMetric(%s) Done", key)
	return &status
}

func publishAppDiskMetrics(ctx *volumemgrContext, statuses ...*types.AppDiskMetric) {
	for _, status := range statuses {
		key := status.Key()
		log.Tracef("publishAppDiskMetrics(%s)", key)
		pub := ctx.pubAppDiskMetric
		pub.Publish(key, *status)
		log.Tracef("publishAppDiskMetrics(%s) Done", key)
	}
}

func unpublishAppDiskMetrics(ctx *volumemgrContext, statuses ...*types.AppDiskMetric) {
	for _, status := range statuses {
		key := status.Key()
		log.Tracef("unpublishAppDiskMetrics(%s)", key)
		pub := ctx.pubAppDiskMetric
		c, _ := pub.Get(key)
		if c == nil {
			log.Errorf("unpublishAppDiskMetrics(%s) not found", key)
			continue
		}
		pub.Unpublish(key)
		log.Tracef("unpublishAppDiskMetrics(%s) Done", key)
	}
}

func lookupAppDiskMetric(ctx *volumemgrContext, key string) *types.AppDiskMetric {
	key = types.PathToKey(key)
	log.Tracef("lookupAppDiskMetric(%s)", key)
	pub := ctx.pubAppDiskMetric
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupAppDiskMetric(%s) not found", key)
		return nil
	}
	status := c.(types.AppDiskMetric)
	log.Tracef("lookupAppDiskMetric(%s) Done", key)
	return &status
}

// diskMetricsTimerTask calculates and publishes disk metrics periodically
func diskMetricsTimerTask(ctx *volumemgrContext, handleChannel chan interface{}) {
	log.Functionln("starting report diskMetricsTimerTask timer task")
	createOrUpdateDiskMetrics(ctx)

	diskMetricInterval := time.Duration(ctx.globalConfig.GlobalValueInt(types.DiskScanMetricInterval)) * time.Second
	max := float64(diskMetricInterval)
	min := max * 0.3
	diskMetricTicker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	// Return handle to caller
	handleChannel <- diskMetricTicker

	wdName := agentName + "metrics"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-diskMetricTicker.C:
			start := time.Now()
			createOrUpdateDiskMetrics(ctx)
			ctx.ps.CheckMaxTimeTopic(wdName, "createOrUpdateDiskMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// createOrUpdateDiskMetrics creates or updates metrics for all disks, mountpaths and volumeStatuses
func createOrUpdateDiskMetrics(ctx *volumemgrContext) {
	log.Functionf("createOrUpdateDiskMetrics")
	var diskMetricList []*types.DiskMetric
	startPubTime := time.Now()

	disks := diskmetrics.FindDisksPartitions(log)
	for _, d := range disks {
		size, _ := diskmetrics.PartitionSize(log, d)
		log.Tracef("createOrUpdateDiskMetrics: Disk/partition %s size %d", d, size)
		var metric *types.DiskMetric
		metric = lookupDiskMetric(ctx, d)
		if metric == nil {
			log.Functionf("createOrUpdateDiskMetrics: creating new DiskMetric for %s", d)
			metric = &(types.DiskMetric{DiskPath: d, IsDir: false})
		} else {
			log.Functionf("createOrUpdateDiskMetrics: updating DiskMetric for %s", d)
		}
		metric.TotalBytes = size
		stat, err := disk.IOCounters(d)
		if err == nil {
			metric.ReadBytes = stat[d].ReadBytes
			metric.WriteBytes = stat[d].WriteBytes
			metric.ReadCount = stat[d].ReadCount
			metric.WriteCount = stat[d].WriteCount
		}
		// XXX do we have a mountpath? Combine with paths below if same?
		diskMetricList = append(diskMetricList, metric)
	}

	var persistUsage uint64
	for _, path := range types.ReportDiskPaths {
		var u *types.UsageStat
		var err error
		if path == types.PersistDir {
			// dedicated handler for PersistDir as we have to use PersistType dependent calculations
			u, err = diskmetrics.PersistUsageStat(log)
			if err != nil {
				// Happens e.g., if we don't have a /persist
				log.Errorf("createOrUpdateDiskMetrics: persistUsageStat: %s", err)
				continue
			}
			// We can not run diskmetrics.SizeFromDir("/persist") below in reportDirPaths, get the usage
			// data here for persistUsage
			persistUsage = u.Used
		} else {
			usage, err := disk.Usage(path)
			if err != nil {
				// Happens e.g., if we don't have a /persist
				log.Errorf("createOrUpdateDiskMetrics: disk.Usage: %s", err)
				continue
			}
			u = &types.UsageStat{
				Total: usage.Total,
				Used:  usage.Used,
				Free:  usage.Free,
			}
		}
		log.Tracef("createOrUpdateDiskMetrics: Path %s total %d used %d free %d",
			path, u.Total, u.Used, u.Free)
		var metric *types.DiskMetric
		metric = lookupDiskMetric(ctx, path)
		if metric == nil {
			log.Functionf("createOrUpdateDiskMetrics: creating new DiskMetric for %s", path)
			metric = &(types.DiskMetric{DiskPath: path, IsDir: true})
		} else {
			log.Functionf("createOrUpdateDiskMetrics: updating DiskMetric for %s", path)
		}
		metric.TotalBytes = u.Total
		metric.UsedBytes = u.Used
		metric.FreeBytes = u.Free
		diskMetricList = append(diskMetricList, metric)
	}
	log.Tracef("createOrUpdateDiskMetrics: persistUsage %d, elapse sec %v", persistUsage, time.Since(startPubTime).Seconds())

	for _, path := range types.ReportDirPaths {
		usage, err := diskmetrics.DirUsage(log, path)
		log.Tracef("createOrUpdateDiskMetrics: ReportDirPath %s usage %d err %v", path, usage, err)
		if err != nil {
			// Do not report
			continue
		}
		var metric *types.DiskMetric
		metric = lookupDiskMetric(ctx, path)
		if metric == nil {
			log.Functionf("createOrUpdateDiskMetrics: creating new DiskMetric for %s", path)
			metric = &(types.DiskMetric{DiskPath: path, IsDir: true})
		} else {
			log.Functionf("createOrUpdateDiskMetrics: updating DiskMetric for %s", path)
		}

		metric.UsedBytes = usage

		diskMetricList = append(diskMetricList, metric)
	}
	log.Tracef("createOrUpdateDiskMetrics: DirPaths in persist, elapse sec %v", time.Since(startPubTime).Seconds())

	for _, path := range types.AppPersistPaths {
		usage, err := diskmetrics.DirUsage(log, path)
		log.Tracef("createOrUpdateDiskMetrics: AppPersistPath %s usage %d err %v", path, usage, err)
		if err != nil {
			// Do not report
			continue
		}
		var metric *types.DiskMetric
		metric = lookupDiskMetric(ctx, path)
		if metric == nil {
			log.Functionf("createOrUpdateDiskMetrics: creating new DiskMetric for %s", path)
			metric = &(types.DiskMetric{DiskPath: path, IsDir: true})
		} else {
			log.Functionf("createOrUpdateDiskMetrics: updating DiskMetric for %s", path)
		}

		metric.UsedBytes = usage

		diskMetricList = append(diskMetricList, metric)
	}
	publishDiskMetrics(ctx, diskMetricList...)
	for _, volumeStatus := range getAllVolumeStatus(ctx) {
		if err := createOrUpdateAppDiskMetrics(ctx, volumeStatus); err != nil {
			log.Errorf("CreateOrUpdateCommonDiskMetrics: exception while publishing diskmetric. %s", err.Error())
		}
	}
}

func createOrUpdateAppDiskMetrics(ctx *volumemgrContext, volumeStatus *types.VolumeStatus) error {
	log.Functionf("createOrUpdateAppDiskMetrics(%s, %s)", volumeStatus.VolumeID, volumeStatus.FileLocation)
	if volumeStatus.FileLocation == "" {
		// Nothing we can do? XXX can we retrieve size from CAS?
		return nil
	}
	actualSize, maxSize, diskType, dirtyFlag, err := volumehandlers.GetVolumeHandler(log, ctx, volumeStatus).GetVolumeDetails()
	if err != nil {
		err = fmt.Errorf("createOrUpdateAppDiskMetrics(%s, %s): exception while getting volume size. %s",
			volumeStatus.VolumeID, volumeStatus.FileLocation, err)
		log.Error(err.Error())
		return err
	}
	appDiskMetric := types.AppDiskMetric{DiskPath: volumeStatus.FileLocation,
		ProvisionedBytes: maxSize,
		UsedBytes:        actualSize,
		DiskType:         diskType,
		Dirty:            dirtyFlag,
	}
	publishAppDiskMetrics(ctx, &appDiskMetric)
	return nil
}
