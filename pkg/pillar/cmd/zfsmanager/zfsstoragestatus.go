// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"strconv"
	"time"

	libzfs "github.com/andrewd-zededa/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

const (
	storageStatusPublishInterval = 30 * time.Second // interval between publishing zfs pool status
)

func storageStatusPublisher(ctxPtr *zfsContext) {
	if vault.ReadPersistType() != types.PersistZFS {
		return
	}
	collectAndPublishStorageStatus(ctxPtr)

	t := time.NewTicker(storageStatusPublishInterval)
	for {
		select {
		case <-t.C:
			collectAndPublishStorageStatus(ctxPtr)
		}
	}
}

func collectAndPublishStorageStatus(ctxPtr *zfsContext) {
	log.Functionf("collectAndPublishStorageStatus start")
	ctxPtr.zfsIterLock.Lock()
	defer ctxPtr.zfsIterLock.Unlock()
	zfsVersion, err := zfs.GetZfsVersion()
	if err != nil {
		log.Errorf("error: %v", err)
	}

	zpoolList, err := libzfs.PoolOpenAll()
	if err != nil {
		log.Errorf("get zpool list failed %v", err)
	} else {
		for _, zpool := range zpoolList {
			status := new(types.ZFSPoolStatus)
			defer zpool.Close()
			currentRaid := types.StorageRaidTypeNoRAID
			zpoolPropName, err := zpool.GetProperty(libzfs.PoolPropName)
			if err != nil {
				log.Errorf("error with get properties PoolPropName %v", err)
				continue
			}

			zpoolPropHealth, err := zpool.GetProperty(libzfs.PoolPropHealth)
			if err != nil {
				log.Errorf("error with get properties PoolPropHealth %v", err)
				continue
			}

			poolStatus, err := zpool.Status()
			if err != nil {
				log.Errorf("error with get zpool status %v", err)
				continue
			}

			zpoolPropSize, err := zpool.GetProperty(libzfs.PoolPropSize)
			if err != nil {
				log.Errorf("error with get properties PoolPropSize %v", err)
				continue
			}

			zpoolName := zpoolPropName.Value
			storageState := zfs.GetZfsDeviceStatusFromStr(zpoolPropHealth.Value)
			zpoolSizeInByte, err := strconv.ParseUint(zpoolPropSize.Value, 10, 64)
			if err != nil {
				log.Errorf("error with ParseUint for get zpool size in byte: %v", err)
			}

			countZvolume, err := zfs.GetZfsCountVolume(zpoolName)
			if err != nil {
				log.Errorf("get count volume failed %v", err)
			}

			compressratio, _ := zfs.GetZfsCompressratio(zpoolName)
			if err != nil {
				log.Errorf("error with ParseFloat for get compression ratio: %v", err)
			}

			vdevs, err := zpool.VDevTree()
			if err != nil {
				log.Errorf("error with get about RAID info from devTree: %v", err)
			} else {
				// it returns top-level raid type
				currentRaid = zfs.GetZpoolRaidType(vdevs)
				// handle the case when we have only one top-level vdev
				if currentRaid != types.StorageRaidTypeRAID0 {
					for _, vdev := range vdevs.Devices {
						// If this is a RAID or mirror, look at the disks it consists of
						if vdev.Type == libzfs.VDevTypeMirror || vdev.Type == libzfs.VDevTypeRaidz {
							for _, disk := range vdev.Devices {
								rDiskStatus, err := zfs.GetZfsDiskAndStatus(disk)
								// vdev.Devices might includes snapshots or caches,
								// and those will result in errors which need to ignore.
								if err == nil {
									status.Disks = append(status.Disks, rDiskStatus)
								}
							}
							break // in that case we have only one RAID
						}
						// If there is no RAID or mirror, add a disk if it is a disk
						rDiskStatus, err := zfs.GetZfsDiskAndStatus(vdev)
						// vdev.Devices might includes snapshots or caches,
						// and those will result in errors which need to ignore.
						if err == nil {
							status.Disks = append(status.Disks, rDiskStatus)
						}
					}
				} else {
					// multiple top-level vdevs should be handled separately
					currentRaid = types.StorageRaidTypeUnspecified
					// if unspecified, use provided
					// if noraid, keep it
					// if lower than current, update
					updateCurrentRaid := func(raidType types.StorageRaidType) {
						if currentRaid == types.StorageRaidTypeUnspecified {
							currentRaid = raidType
							return
						}
						if currentRaid == types.StorageRaidTypeNoRAID {
							return
						}
						if raidType < currentRaid {
							currentRaid = raidType
							return
						}
					}
					for _, vdev := range vdevs.Devices {
						child := new(types.StorageChildren)
						child.DisplayName = vdev.Name // Not unique to VDevTypeRaidz and VDevTypeMirror
						// If this is a RAID or mirror, look at the disks it consists of
						if vdev.Type == libzfs.VDevTypeMirror || vdev.Type == libzfs.VDevTypeRaidz {
							child.CurrentRaid = zfs.GetRaidTypeFromStr(vdev.Name)
							child.GUID = vdev.GUID
							updateCurrentRaid(child.CurrentRaid)
							for _, disk := range vdev.Devices {
								rDiskStatus, err := zfs.GetZfsDiskAndStatus(disk)
								// vdev.Devices might includes snapshots or caches,
								// and those will result in errors which need to ignore.
								if err == nil {
									child.Disks = append(child.Disks, rDiskStatus)
								}
							}
							status.Children = append(status.Children, child)
							continue
						}
						// If there is no RAID or mirror, add a disk if it is a disk
						rDiskStatus, err := zfs.GetZfsDiskAndStatus(vdev)
						// vdev.Devices might includes snapshots or caches,
						// and those will result in errors which need to ignore.
						if err == nil {
							child.CurrentRaid = types.StorageRaidTypeNoRAID
							updateCurrentRaid(child.CurrentRaid)
							child.Disks = append(child.Disks, rDiskStatus)
							status.Children = append(status.Children, child)
						}
					}
					// unspecified or raid0 gives no redundancy, so noraid here
					if currentRaid == types.StorageRaidTypeUnspecified ||
						currentRaid == types.StorageRaidTypeRAID0 {
						currentRaid = types.StorageRaidTypeNoRAID
					}
				}
			}
			status.PoolName = zpoolName
			status.PoolStatusMsg = types.PoolStatus(poolStatus + 1) // + 1 given the presence of PoolStatusUnspecified on the EVE side
			status.PoolStatusMsgStr = zfs.GetZpoolStatusMsgStr(status.PoolStatusMsg)
			status.ZpoolSize = zpoolSizeInByte
			status.ZfsVersion = zfsVersion
			status.CurrentRaid = currentRaid
			status.CompressionRatio = compressratio
			status.CountZvols = countZvolume
			status.StorageState = storageState
			if err := ctxPtr.storageStatusPub.Publish(status.Key(), *status); err != nil {
				log.Errorf("error in publishing of storageStatus: %s", err)
			}
		}
	}
	log.Functionf("collectAndPublishStorageStatus Done")
}
