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
		// we start consume space when moving into CREATING_VOLUME state
		if iterVolumeStatus.State < types.CREATING_VOLUME {
			log.Tracef("Volume %s State %d < CREATING_VOLUME",
				iterVolumeStatus.Key(), iterVolumeStatus.State)
			continue
		}
		totalDiskSize += volumehandlers.GetVolumeHandler(log, ctxPtr, &iterVolumeStatus).UsageFromStatus()
	}
	deviceDiskUsage, err := diskmetrics.PersistUsageStat(log)
	if err != nil {
		err := fmt.Errorf("Failed to get diskUsage for /persist. err: %s", err)
		log.Error(err)
		return 0, err
	}
	deviceDiskSize := deviceDiskUsage.Total
	diskReservedForDom0 := diskmetrics.Dom0DiskReservedSize(log, ctxPtr.globalConfig, deviceDiskSize)
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
