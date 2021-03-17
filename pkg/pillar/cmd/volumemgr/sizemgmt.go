// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/disk"
)

// getRemainingDiskSpace returns how many bytes remain for volume
// and content tree usage
// disk usage (latter used if there isn't enough)
func getRemainingDiskSpace(ctxPtr *volumemgrContext) (uint64, error) {

	var totalDiskSize uint64

	pubContentTree := ctxPtr.pubContentTreeStatus
	itemsContentTree := pubContentTree.GetAll()
	for _, iterContentTreeStatusJSON := range itemsContentTree {
		iterContentTreeStatus := iterContentTreeStatusJSON.(types.ContentTreeStatus)
		if iterContentTreeStatus.State < types.LOADED {
			log.Tracef("Content tree %s State %d < LOADED",
				iterContentTreeStatus.Key(), iterContentTreeStatus.State)
			continue
		}
		totalDiskSize += uint64(iterContentTreeStatus.CurrentSize)
	}

	pubVolume := ctxPtr.pubVolumeStatus
	itemsVolume := pubVolume.GetAll()
	for _, iterVolumeStatusJSON := range itemsVolume {
		iterVolumeStatus := iterVolumeStatusJSON.(types.VolumeStatus)
		if iterVolumeStatus.State < types.CREATED_VOLUME {
			log.Tracef("Volume %s State %d < CREATED_VOLUME",
				iterVolumeStatus.Key(), iterVolumeStatus.State)
			continue
		}
		cfg := lookupVolumeConfig(ctxPtr, iterVolumeStatus.Key())
		if cfg != nil && !cfg.ReadOnly && !cfg.HasNoAppReferences {
			totalDiskSize += iterVolumeStatus.MaxVolSize
		} else {
			// we have no config with this volume, so it will purged soon
			// or it is ReadOnly and will not grow
			// or it has no apps pointing onto it in new config
			totalDiskSize += uint64(iterVolumeStatus.CurrentSize)
		}
	}
	deviceDiskUsage, err := disk.Usage(types.PersistDir)
	if err != nil {
		err := fmt.Errorf("Failed to get diskUsage for /persist. err: %s", err)
		log.Error(err)
		return 0, err
	}
	deviceDiskSize := deviceDiskUsage.Total
	diskReservedForDom0 := dom0DiskReservedSize(ctxPtr, deviceDiskSize)
	var allowedDeviceDiskSize uint64
	if deviceDiskSize < diskReservedForDom0 {
		err = fmt.Errorf("Total Disk Size(%d) <=  diskReservedForDom0(%d)",
			deviceDiskSize, diskReservedForDom0)
		log.Errorf("***getRemainingDiskSpace: err: %s", err)
		return uint64(0), err
	}
	allowedDeviceDiskSize = deviceDiskSize - diskReservedForDom0
	if allowedDeviceDiskSize < totalDiskSize {
		return 0, nil
	} else {
		return allowedDeviceDiskSize - totalDiskSize, nil
	}
}

func dom0DiskReservedSize(ctxPtr *volumemgrContext, deviceDiskSize uint64) uint64 {
	dom0MinDiskUsagePercent := ctxPtr.globalConfig.GlobalValueInt(
		types.Dom0MinDiskUsagePercent)
	diskReservedForDom0 := uint64(float64(deviceDiskSize) *
		(float64(dom0MinDiskUsagePercent) * 0.01))
	maxDom0DiskSize := uint64(ctxPtr.globalConfig.GlobalValueInt(
		types.Dom0DiskUsageMaxBytes))
	if diskReservedForDom0 > maxDom0DiskSize {
		log.Tracef("diskSizeReservedForDom0 - diskReservedForDom0 adjusted to "+
			"maxDom0DiskSize (%d)", maxDom0DiskSize)
		diskReservedForDom0 = maxDom0DiskSize
	}
	return diskReservedForDom0
}
