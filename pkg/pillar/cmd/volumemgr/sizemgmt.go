// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/disk"
)

// getRemainingDiskSpace returns how many bytes remain for volume and content
// tree usage plus a string for printing the current volume and content tree
// disk usage (latter used if there isn't enough)
func getRemainingDiskSpace(ctxPtr *volumemgrContext) (uint64, string, error) {

	var totalDiskSize uint64
	diskSizeList := "" // In case caller wants to print an error

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
		diskSizeList += fmt.Sprintf("Content tree: %s (Size: %d)\n",
			iterContentTreeStatus.Key(), iterContentTreeStatus.CurrentSize)
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
		totalDiskSize += iterVolumeStatus.MaxVolSize
		diskSizeList += fmt.Sprintf("Volume: %s (Size: %d)\n",
			iterVolumeStatus.Key(), iterVolumeStatus.MaxVolSize)
	}
	deviceDiskUsage, err := disk.Usage(types.PersistDir)
	if err != nil {
		err := fmt.Errorf("Failed to get diskUsage for /persist. err: %s", err)
		log.Error(err)
		return 0, diskSizeList, err
	}
	deviceDiskSize := deviceDiskUsage.Total
	diskReservedForDom0 := dom0DiskReservedSize(ctxPtr, deviceDiskSize)
	var allowedDeviceDiskSize uint64
	if deviceDiskSize < diskReservedForDom0 {
		err = fmt.Errorf("Total Disk Size(%d) <=  diskReservedForDom0(%d)",
			deviceDiskSize, diskReservedForDom0)
		log.Errorf("***getRemainingDiskSpace: err: %s", err)
		return uint64(0), diskSizeList, err
	}
	allowedDeviceDiskSize = deviceDiskSize - diskReservedForDom0
	if allowedDeviceDiskSize < totalDiskSize {
		return 0, diskSizeList, nil
	} else {
		return allowedDeviceDiskSize - totalDiskSize, diskSizeList, nil
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
