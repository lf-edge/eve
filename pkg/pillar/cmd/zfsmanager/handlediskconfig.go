// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	libzfs "github.com/andrewd-zededa/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/disks"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// getVDevState returns vDev state from zfs if found
// it processes name of vDev to remove partition and check that provided vDevName contains device
// vDevName may be in form /dev/sda, /dev/sda9, sda, sda9
func getVDevState(devTree libzfs.VDevTree, vDevName string) *libzfs.VDevState {
	if vDevName == "" {
		return nil
	}
	if devTree.Type != libzfs.VDevTypeDisk {
		for _, d := range devTree.Devices {
			retState := getVDevState(d, vDevName)
			if retState != nil {
				return retState
			}
		}
		return nil
	}
	// we can receive partition for example /dev/sda1
	devName, err := disks.GetDiskNameByPartName(devTree.Name)
	if err != nil {
		log.Errorf("failed to get disk name by part name %s: %s", devTree.Name, err)
		return nil
	}
	if strings.Contains(vDevName, filepath.Base(devName)) {
		return &devTree.Stat.State
	}
	return nil
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
	if persist.ReadPersistType() != types.PersistZFS {
		return nil
	}
	disksConfigInterface, err := ctx.subDisksConfig.Get("global")
	if err != nil {
		log.Functionf("cannot get disks config: %s", err)
		return nil
	}
	disksConfig := disksConfigInterface.(types.EdgeNodeDisks)
	persistPool, err := libzfs.PoolOpen(types.PersistPool)
	if err != nil {
		return fmt.Errorf("cannot open pool: %s", err)
	}
	disksStateProcessing(disksConfig, persistPool)
	persistPool.Close()
	// re-read pool to grab changes after disksStateProcessing
	persistPool, err = libzfs.PoolOpen(types.PersistPool)
	if err != nil {
		return fmt.Errorf("cannot open pool: %s", err)
	}
	disksLayoutProcessing(disksConfig, persistPool)
	persistPool.Close()
	return nil
}

// disksStateProcessing iterate over disks and adjust its state accordingly to the config
// we expect that zfs will handle conflicts between order of calls
func disksStateProcessing(disks types.EdgeNodeDisks, pool libzfs.Pool) {
	vdevTree, err := pool.VDevTree()
	if err != nil {
		log.Errorf("cannot get vdev tree: %s", err)
		return
	}
	for _, diskCfg := range disks.Disks {
		if diskCfg.OldDisk != nil {
			oldDevState := getVDevState(vdevTree, diskCfg.OldDisk.Name)
			if oldDevState != nil && diskCfg.Disk.Name != "" {
				// if we found device oldDevName, replace it
				log.Functionf("replacing %s with %s, old stat %s", diskCfg.OldDisk.Name, diskCfg.Disk.Name, oldDevState.String())
				if stdout, err := zfs.ReplaceVDev(log, types.PersistPool, diskCfg.OldDisk.Name, diskCfg.Disk.Name); err != nil {
					log.Errorf("cannot replace %s with %s: %s %s", diskCfg.OldDisk.Name, diskCfg.Disk.Name, stdout, err)
					continue
				}
			}
		}
		devState := getVDevState(vdevTree, diskCfg.Disk.Name)
		// found in pool
		if devState != nil {
			log.Functionf("zpool config disk %s, op %d, stat %s", diskCfg.Disk.Name, diskCfg.Config, devState.String())
			switch diskCfg.Config {
			case types.EdgeNodeDiskConfigTypeZfsOnline:
				switch zfs.GetZfsDeviceStatusFromStr(devState.String()) {
				case types.StorageStatusOffline:
					if err := pool.Online(true, diskCfg.Disk.Name); err != nil {
						log.Errorf("cannot bring %s online: %s", diskCfg.Disk.Name, err)
					}
				case types.StorageStatusOnline:
					continue
				default:
					log.Errorf("unexpected state of disk %s (%s) to make online", diskCfg.Disk.Name, devState.String())
					continue
				}
			case types.EdgeNodeDiskConfigTypeZfsOffline:
				switch zfs.GetZfsDeviceStatusFromStr(devState.String()) {
				case types.StorageStatusOnline:
					if err := pool.Offline(true, diskCfg.Disk.Name); err != nil {
						log.Errorf("cannot bring %s offline: %s", diskCfg.Disk.Name, err)
					}
				case types.StorageStatusOffline:
					continue
				default:
					log.Errorf("unexpected state of disk %s (%s) to make offline", diskCfg.Disk.Name, devState.String())
					continue
				}
			case types.EdgeNodeDiskConfigTypeUnused:
				if stdout, err := zfs.RemoveVDev(log, types.PersistPool, diskCfg.Disk.Name); err != nil {
					log.Errorf("cannot remove %s: %s %s", diskCfg.Disk.Name, stdout, err)
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

// disksLayoutProcessing iterate over disks and adjust pool layout accordingly to the config
func disksLayoutProcessing(disks types.EdgeNodeDisks, pool libzfs.Pool) {
	vdevTree, err := pool.VDevTree()
	if err != nil {
		log.Errorf("cannot get vdev tree: %s", err)
		return
	}
	switch disks.ArrayType {
	case types.EdgeNodeDiskArrayTypeRAID0:
		disksLayoutRaid0Process(vdevTree, disks.Children)
	case types.EdgeNodeDiskArrayTypeUnspecified:
	default:
		// TBD: other array types
		log.Warnf("Not implemented layout processing for array type: %d", disks.ArrayType)
	}
}

// disksLayoutRaid0Process ensure layout for batch of top-level vdevs in pool
// we support raid0 of unspecified (single disk) and raid1 (mirror of disks) layout here
func disksLayoutRaid0Process(vdevTree libzfs.VDevTree, disks []types.EdgeNodeDisks) {
	for _, el := range disks {
		switch el.ArrayType {
		case types.EdgeNodeDiskArrayTypeUnspecified, types.EdgeNodeDiskArrayTypeRAID1:
			diskName := ""
			// check if we have one of defined devices as part of vdev
			for _, dsk := range el.Disks {
				if devState := getVDevState(vdevTree, dsk.Disk.Name); devState != nil {
					diskName = dsk.Disk.Name
					break
				}
			}
			// if no disk found add first as a new vdev
			if diskName == "" {
				if len(el.Disks) > 0 {
					// we add first device here as a new vdev to attach needed disks to it later
					if stdout, err := zfs.AddVDev(log, types.PersistPool, el.Disks[0].Disk.Name); err != nil {
						log.Errorf("cannot add %s: %s %s", el.Disks[0].Disk.Name, stdout, err)
					} else {
						diskName = el.Disks[0].Disk.Name
					}
				}
			}
			// if disk is here attach another disks
			if diskName != "" {
				for _, dsk := range el.Disks {
					// check if added as part of current iteration (we do not refresh the tree)
					if diskName == dsk.Disk.Name {
						continue
					}
					// check if already in pool
					if devState := getVDevState(vdevTree, dsk.Disk.Name); devState != nil {
						continue
					}
					if stdout, err := zfs.AttachVDev(log, types.PersistPool, diskName, dsk.Disk.Name); err != nil {
						log.Errorf("cannot attach %s to %s: %s %s", dsk.Disk.Name, diskName, stdout, err)
					}
				}
			}
		default:
			log.Warnf("No supported child processing for array type: %d", el.ArrayType)
		}
	}
}
