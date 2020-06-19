// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/disk"
	log "github.com/sirupsen/logrus"
)

// getRemainingVolumeDiskSpace returns how many bytes remain for volume usage
// plus a string for printing the current volume disk usage (latter used
// if there isn't enough)
func getRemainingVolumeDiskSpace(ctxPtr *volumemgrContext) (uint64, string, error) {

	var totalVolumeDiskSize uint64
	volumeDiskSizeList := "" // In case caller wants to print an error

	pub := ctxPtr.pubVolumeStatus
	items := pub.GetAll()
	for _, iterStatusJSON := range items {
		iterStatus := iterStatusJSON.(types.VolumeStatus)
		if iterStatus.State < types.CREATED_VOLUME {
			log.Debugf("Volume %s State %d < CREATED_VOLUME",
				iterStatus.Key(), iterStatus.State)
			continue
		}
		totalVolumeDiskSize += iterStatus.MaxVolSize
		volumeDiskSizeList += fmt.Sprintf("Volume: %s (Size: %d)\n",
			iterStatus.Key(), iterStatus.MaxVolSize)
	}
	deviceDiskUsage, err := disk.Usage(types.PersistDir)
	if err != nil {
		err := fmt.Errorf("Failed to get diskUsage for /persist. err: %s", err)
		log.Error(err)
		return 0, volumeDiskSizeList, err
	}
	deviceDiskSize := deviceDiskUsage.Total
	diskReservedForDom0 := dom0DiskReservedSize(ctxPtr, deviceDiskSize)
	var allowedDeviceDiskSizeForVolumes uint64
	if deviceDiskSize < diskReservedForDom0 {
		err = fmt.Errorf("Total Disk Size(%d) <=  diskReservedForDom0(%d)",
			deviceDiskSize, diskReservedForDom0)
		log.Errorf("***getRemainingVolumeDiskSpace: err: %s", err)
		return uint64(0), volumeDiskSizeList, err
	}
	allowedDeviceDiskSizeForVolumes = deviceDiskSize - diskReservedForDom0
	if allowedDeviceDiskSizeForVolumes < totalVolumeDiskSize {
		return 0, volumeDiskSizeList, nil
	} else {
		return allowedDeviceDiskSizeForVolumes - totalVolumeDiskSize, volumeDiskSizeList, nil
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
		log.Debugf("diskSizeReservedForDom0 - diskReservedForDom0 adjusted to "+
			"maxDom0DiskSize (%d)", maxDom0DiskSize)
		diskReservedForDom0 = maxDom0DiskSize
	}
	return diskReservedForDom0
}
