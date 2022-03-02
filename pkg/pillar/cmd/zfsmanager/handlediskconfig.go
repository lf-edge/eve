// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/disks"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

func getVdevNameAndStatus(devTree libzfs.VDevTree, name string) (string, libzfs.VDevStat) {
	if devTree.Type != libzfs.VDevTypeDisk {
		for _, d := range devTree.Devices {
			retDev, retStat := getVdevNameAndStatus(d, name)
			if retDev != "" {
				return retDev, retStat
			}
		}
	} else {
		// we can receive partition number
		devName, err := disks.GetDiskNameByPartName(devTree.Name)
		if err != nil {
			log.Errorf("failed to get disk name by part name %s: %s", devTree.Name, err)
		}
		if strings.Contains(devName, name) {
			return devName, devTree.Stat
		}
	}
	return "", libzfs.VDevStat{}
}

func handleDisksConfigCreate(ctxArg interface{}, _ string, _ interface{}) {
	handleDisksConfigImpl(ctxArg.(*zfsContext))
}

func handleDisksConfigModify(ctxArg interface{}, _ string, _ interface{}, _ interface{}) {
	handleDisksConfigImpl(ctxArg.(*zfsContext))
}

func handleDisksConfigImpl(ctx *zfsContext) {
	log.Functionf("handleDisksConfigImpl")
	select {
	case ctx.disksProcessingTrigger <- struct{}{}:
	default:
		log.Functionf("handleDiskConfigRestart: disksProcessingTrigger already triggered")
	}
	log.Functionf("handleDisksConfigImpl Done")
}

func processDisksTask(ctx *zfsContext) {

	disksProcessingTicker := time.NewTicker(disksProcessingInterval)

	wdName := agentName + "diskstask"
	stillRunning := time.NewTicker(stillRunningInterval)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)

	for {
		select {
		case <-disksProcessingTicker.C:
			// we run processing periodically to ensure that our expectation and states/layout are in sync
			// potentially some commands may return errors in case of not-ended operations
			// we should cover hot-plugged devices
			if err := processDisks(ctx); err != nil {
				log.Errorf("processDisks error: %s", err)
			}
		case <-ctx.disksProcessingTrigger:
			if err := processDisks(ctx); err != nil {
				log.Errorf("processDisks error: %s", err)
			}
		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func processDisks(ctx *zfsContext) error {
	if vault.ReadPersistType() != types.PersistZFS {
		return nil
	}
	disksConfigInterface, err := ctx.subDisksConfig.Get("global")
	if err != nil {
		log.Functionf("cannot get disks config: %s", err)
		return nil
	}
	disksConfig := disksConfigInterface.(types.EdgeNodeDisks)
	persistPool, err := libzfs.PoolOpen(vault.DefaultZpool)
	if err != nil {
		return fmt.Errorf("cannot open pool: %s", err)
	}
	defer persistPool.Close()
	disksStateProcessing(disksConfig, persistPool)
	disksLayoutProcessing(disksConfig, persistPool)
	return nil
}

//disksStateProcessing iterate over disks and adjust its state accordingly to the config
//we expect that zfs will handle conflicts between order of calls
func disksStateProcessing(disks types.EdgeNodeDisks, pool libzfs.Pool) {
	vdevTree, err := pool.VDevTree()
	if err != nil {
		log.Errorf("cannot get vdev tree: %s", err)
		return
	}
	for _, diskCfg := range disks.Disks {
		diskName := filepath.Base(diskCfg.Disk.Name)
		if diskCfg.OldDisk != nil {
			oldDiskName := filepath.Base(diskCfg.OldDisk.Name)
			oldDevName, oldDevStat := getVdevNameAndStatus(vdevTree, oldDiskName)
			if oldDevName != "" && diskCfg.Disk.Name != "" {
				// if we found device oldDevName, replace it
				log.Functionf("replacing %s with %s, old stat %s", oldDevName, diskCfg.Disk.Name, oldDevStat.State.String())
				if stdout, err := zfs.ReplaceVDev(log, vault.DefaultZpool, oldDevName, diskCfg.Disk.Name); err != nil {
					log.Errorf("cannot replace %s with %s: %s %s", oldDevName, diskCfg.Disk.Name, stdout, err)
					continue
				}
			}
		}
		devName, devStat := getVdevNameAndStatus(vdevTree, diskName)
		// found in pool
		if devName != "" {
			log.Functionf("zpool config disk %s, op %d, stat %s", devName, diskCfg.Config, devStat.State.String())
			switch diskCfg.Config {
			case types.EdgeNodeDiskConfigTypeZfsOnline:
				switch zfs.GetZfsDeviceStatusFromStr(devStat.State.String()) {
				case types.StorageStatusOffline:
					if err := pool.Online(true, devName); err != nil {
						log.Errorf("cannot bring %s online: %s", devName, err)
					}
				case types.StorageStatusOnline:
					continue
				default:
					log.Errorf("unexpected state of disk %s (%s) to make online", devName, devStat.State.String())
					continue
				}
			case types.EdgeNodeDiskConfigTypeZfsOffline:
				switch zfs.GetZfsDeviceStatusFromStr(devStat.State.String()) {
				case types.StorageStatusOnline:
					if err := pool.Offline(true, devName); err != nil {
						log.Errorf("cannot bring %s offline: %s", devName, err)
					}
				case types.StorageStatusOffline:
					continue
				default:
					log.Errorf("unexpected state of disk %s (%s) to make offline", devName, devStat.State.String())
					continue
				}
			case types.EdgeNodeDiskConfigTypeUnused:
				if stdout, err := zfs.RemoveVDev(log, vault.DefaultZpool, devName); err != nil {
					log.Errorf("cannot remove %s: %s %s", devName, stdout, err)
				}
			}
		}
	}
	for _, el := range disks.Children {
		// process children states
		// we process only states of devices as part of vdevs, so we assume that we can handle them in any order
		disksStateProcessing(el, pool)
	}
}

//disksLayoutProcessing iterate over disks and adjust pool layout accordingly to the config
func disksLayoutProcessing(disks types.EdgeNodeDisks, pool libzfs.Pool) {
	vdevTree, err := pool.VDevTree()
	if err != nil {
		log.Errorf("cannot get vdev tree: %s", err)
		return
	}
	switch disks.ArrayType {
	case types.EdgeNodeDiskArrayTypeRAID0:
		disksLayoutRaid0Process(vdevTree, disks.Children)
	default:
		// TBD: other array types
		log.Warnf("Not implemented layout processing for array type: %d", disks.ArrayType)
	}
}

//disksLayoutRaid0Process ensure layout for batch of top-level vdevs in pool
//we support raid0 of unspecified (single disk) and raid1 (mirror of disks) layout here
func disksLayoutRaid0Process(vdevTree libzfs.VDevTree, disks []types.EdgeNodeDisks) {
	for _, el := range disks {
		switch el.ArrayType {
		case types.EdgeNodeDiskArrayTypeUnspecified, types.EdgeNodeDiskArrayTypeRAID1:
			diskName := ""
			// check if we have one of defined devices as part of vdev
			for _, dsk := range el.Disks {
				if currentDiskName, _ := getVdevNameAndStatus(vdevTree, dsk.Disk.Name); currentDiskName != "" {
					diskName = dsk.Disk.Name
					break
				}
			}
			// if no disk found add first as a new vdev
			if diskName == "" {
				if len(el.Disks) > 0 {
					// we add first device here as a new vdev to attach needed disks to it later
					if stdout, err := zfs.AddVDev(log, vault.DefaultZpool, el.Disks[0].Disk.Name); err != nil {
						log.Errorf("cannot add %s: %s %s", diskName, stdout, err)
					} else {
						diskName = el.Disks[0].Disk.Name
					}
				}
			}
			// if disk is here attach another disks
			if diskName != "" {
				for _, dsk := range el.Disks {
					// check if already in pool or added as part of current iteration (we do not refresh the tree)
					if currentDiskName, _ := getVdevNameAndStatus(vdevTree, dsk.Disk.Name); currentDiskName != "" || diskName == dsk.Disk.Name {
						continue
					}
					if stdout, err := zfs.AttachVDev(log, vault.DefaultZpool, diskName, dsk.Disk.Name); err != nil {
						log.Errorf("cannot attach %s to %s: %s %s", dsk.Disk.Name, diskName, stdout, err)
					}
				}
			}
		default:
			log.Warnf("No supported child processing for array type: %d", el.ArrayType)
		}
	}
}
