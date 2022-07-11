// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"

	"github.com/containerd/containerd/mount"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
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
		// we start consume space when moving into CREATING_VOLUME state
		if iterVolumeStatus.State < types.CREATING_VOLUME {
			log.Tracef("Volume %s State %d < CREATING_VOLUME",
				iterVolumeStatus.Key(), iterVolumeStatus.State)
			continue
		}
		cfg := lookupVolumeConfig(ctxPtr, iterVolumeStatus.Key())
		sizeToUseInCalculation := uint64(iterVolumeStatus.CurrentSize)
		if cfg == nil {
			// we have no config with this volume, so it will be purged
			log.Noticef("getRemainingDiskSpace: Volume %s not found in VolumeConfigs, ignore",
				iterVolumeStatus.Key())
			continue
		}
		if vault.ReadPersistType() == types.PersistZFS {
			log.Noticef("getRemainingDiskSpace: Volume %s is zvol, use MaxVolSize",
				iterVolumeStatus.Key())
			sizeToUseInCalculation = iterVolumeStatus.MaxVolSize
		} else if cfg.ReadOnly {
			// it is ReadOnly and will not grow
			log.Noticef("getRemainingDiskSpace: Volume %s is ReadOnly, use CurrentSize",
				iterVolumeStatus.Key())
		} else if cfg.HasNoAppReferences {
			// it has no apps pointing onto it in new config
			log.Noticef("getRemainingDiskSpace: Volume %s has no app references, use CurrentSize",
				iterVolumeStatus.Key())
		} else {
			// use MaxVolSize in other cases
			log.Noticef("getRemainingDiskSpace: Use MaxVolSize for Volume %s",
				iterVolumeStatus.Key())
			sizeToUseInCalculation = iterVolumeStatus.MaxVolSize
		}
		totalDiskSize += sizeToUseInCalculation
	}
	deviceDiskUsage, err := persistUsageStat(ctxPtr)
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

// persistUsageStat returns usage stat for persist
// We need to handle ZFS differently since the mounted /persist does not indicate
// usage of zvols and snapshots
// Note that we subtract usage of persist/reserved dataset (about 20% of persist capacity)
func persistUsageStat(_ *volumemgrContext) (*types.UsageStat, error) {
	if vault.ReadPersistType() != types.PersistZFS {
		deviceDiskUsage, err := disk.Usage(types.PersistDir)
		if err != nil {
			return nil, err
		}
		usageStat := &types.UsageStat{
			Total: deviceDiskUsage.Total,
			Used:  deviceDiskUsage.Used,
			Free:  deviceDiskUsage.Free,
		}
		return usageStat, nil
	}
	usageStat, err := zfs.GetDatasetUsageStat(types.PersistDataset)
	if err != nil {
		return nil, err
	}
	usageStatReserved, err := zfs.GetDatasetUsageStat(types.PersistReservedDataset)
	if err != nil {
		log.Errorf("GetDatasetUsageStat: %s", err)
	} else {
		// subtract reserved dataset Total from persist Total
		// we use LogicalUsed for usageStat.Total of persist for usageStat.Free calculation
		// so need to subtract
		usageStat.Free -= usageStatReserved.Total
		usageStat.Total -= usageStatReserved.Total
	}
	return usageStat, nil
}

// dirUsage calculates usage of directory
// it checks if provided directory is zfs mountpoint and take usage from zfs in that case
func dirUsage(_ *volumemgrContext, dir string) (uint64, error) {
	if vault.ReadPersistType() != types.PersistZFS || !strings.HasPrefix(dir, types.PersistDir) {
		return diskmetrics.SizeFromDir(log, dir)
	}
	mi, err := mount.Lookup(dir)
	if err != nil {
		// Lookup do not return error in case of dir is not mountpoint
		// it returns the longest found parent mountpoint for provided dir
		log.Errorf("dirUsage: Lookup returns error (%s), fallback to SizeFromDir", err)
		return diskmetrics.SizeFromDir(log, dir)
	}
	// if it is zfs mountpoint and we mount exactly the directory of interest (not parent folder)
	if mi.FSType == types.PersistZFS.String() && mi.Mountpoint == dir {
		usageStat, err := zfs.GetDatasetUsageStat(strings.TrimPrefix(dir, "/"))
		if err != nil {
			return 0, err
		}
		return usageStat.Used, nil
	}
	return diskmetrics.SizeFromDir(log, dir)
}
