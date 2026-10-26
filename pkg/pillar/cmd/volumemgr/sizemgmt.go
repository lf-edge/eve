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
	reservedAppDiskUsage := reservedContentTreeDiskUsage(ctxPtr)

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

// reservedContentTreeDiskUsage returns the disk space used by the blobs of
// all content trees in LOADED state or later. Blobs are keyed by sha256 and
// stored once in the CAS even when several content trees reference them (e.g.
// one content tree per app instance using the same image), so each blob is
// counted only once instead of summing ContentTreeStatus.CurrentSize.
func reservedContentTreeDiskUsage(ctxPtr *volumemgrContext) uint64 {
	var reserved uint64
	counted := make(map[string]struct{})

	for _, iterContentTreeStatusJSON := range ctxPtr.pubContentTreeStatus.GetAll() {
		iterContentTreeStatus := iterContentTreeStatusJSON.(types.ContentTreeStatus)
		if iterContentTreeStatus.State < types.LOADED {
			log.Tracef("Content tree %s State %d < LOADED",
				iterContentTreeStatus.Key(), iterContentTreeStatus.State)
			continue
		}
		for _, blobSha := range iterContentTreeStatus.Blobs {
			if _, ok := counted[blobSha]; ok {
				continue
			}
			counted[blobSha] = struct{}{}
			blob := ctxPtr.LookupBlobStatus(blobSha)
			if blob == nil {
				log.Warnf("reservedContentTreeDiskUsage: content tree %s blob %s not found",
					iterContentTreeStatus.Key(), blobSha)
				continue
			}
			reserved += uint64(blob.CurrentSize)
		}
	}
	return reserved
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
