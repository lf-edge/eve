// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
)

// getRemainingDiskSpace returns how many bytes remain for volume
// and content tree usage
// disk usage (latter used if there isn't enough)
func getRemainingDiskSpace(ctxPtr *volumemgrContext) (uint64, error) {
	var reservedAppDiskUsage uint64

	pubContentTree := ctxPtr.pubContentTreeStatus
	itemsContentTree := pubContentTree.GetAll()
	for _, iterContentTreeStatusJSON := range itemsContentTree {
		iterContentTreeStatus := iterContentTreeStatusJSON.(types.ContentTreeStatus)
		if iterContentTreeStatus.State < types.LOADED {
			log.Tracef("Content tree %s State %d < LOADED",
				iterContentTreeStatus.Key(), iterContentTreeStatus.State)
			continue
		}
		reservedAppDiskUsage += uint64(iterContentTreeStatus.CurrentSize)
	}

	pubVolume := ctxPtr.pubVolumeStatus
	itemsVolume := pubVolume.GetAll()
	for _, iterVolumeStatusJSON := range itemsVolume {
		iterVolumeStatus := iterVolumeStatusJSON.(types.VolumeStatus)
		// we start consume space when moving into CREATING_VOLUME state
		if iterVolumeStatus.State < types.CREATING_VOLUME {
			log.Tracef("Volume %s State %d < CREATING_VOLUME",
				iterVolumeStatus.Key(), iterVolumeStatus.State)
			continue
		}
		reservedAppDiskUsage += volumehandlers.GetVolumeHandler(log, ctxPtr, &iterVolumeStatus).UsageFromStatus()
	}
	deviceDiskUsage, err := diskmetrics.PersistUsageStat(log)
	if err != nil {
		err := fmt.Errorf("Failed to get diskUsage for /persist. err: %s", err)
		log.Error(err)
		return 0, err
	}
	deviceDiskSize := deviceDiskUsage.Total // This excludes any ZFS reserved space
	// Subtract the current storage for the volumes and content trees, and
	// also /persist/newlog. Dom0DiskReservedSize will take into account
	// the max size for /persist/newlog
	appDiskUsage := currentAppDiskUsage(ctxPtr)
	var usedByDom0 uint64
	if deviceDiskUsage.Used < appDiskUsage {
		// The appDiskUsage could be several minutes old hence stale
		log.Noticef("dynamic dom0 disk overhead would be negative %d vs. %d",
			deviceDiskUsage.Used, appDiskUsage)
	} else {
		usedByDom0 = deviceDiskUsage.Used - appDiskUsage
	}
	diskReservedForDom0 := diskmetrics.Dom0DiskReservedSize(log, ctxPtr.globalConfig, deviceDiskSize, usedByDom0)
	var allowedDeviceDiskSize uint64
	if deviceDiskSize < diskReservedForDom0 {
		err = fmt.Errorf("Total Disk Size(%d) <=  diskReservedForDom0(%d)",
			deviceDiskSize, diskReservedForDom0)
		log.Errorf("***getRemainingDiskSpace: err: %s", err)
		return uint64(0), err
	}
	allowedDeviceDiskSize = deviceDiskSize - diskReservedForDom0
	log.Noticef("getRemainingDiskSpace device total %d used %d free %d, allowed %d reservedAppDiskUsage %d",
		deviceDiskUsage.Total, deviceDiskUsage.Used, deviceDiskUsage.Free,
		allowedDeviceDiskSize, reservedAppDiskUsage)
	if allowedDeviceDiskSize < reservedAppDiskUsage {
		log.Noticef("getRemainingDiskSpace: ZERO")
		return 0, nil
	} else {
		log.Noticef("getRemainingDiskSpace: %d",
			allowedDeviceDiskSize-reservedAppDiskUsage)
		return allowedDeviceDiskSize - reservedAppDiskUsage, nil
	}
}

// Everything in /persist except these directories/datasets counts
// as EVE overhead.
// Note that we also exclude /persist/newlog here since it maintains its own
// size limit (GlobalValueInt(types.LogRemainToSendMBytes)) the caller
// needs to consider as EVE overhead.
var excludeDirs = append(types.AppPersistPaths, types.NewlogDir)

func currentAppDiskUsage(ctx *volumemgrContext) uint64 {
	// Use the periodically updated DiskMetric
	var appUsage uint64
	for _, dir := range excludeDirs {
		item, err := ctx.pubDiskMetric.Get(types.PathToKey(dir))
		if err != nil {
			log.Warnf("Missing AppUsage directory info for %s", dir)
			continue
		}
		dm := item.(types.DiskMetric)
		appUsage += dm.UsedBytes
	}
	return appUsage
}
