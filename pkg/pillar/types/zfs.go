// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
)

const (
	// ZVolDevicePrefix controlled by mdev
	ZVolDevicePrefix = "/dev/zvol"

	//ZFSSnapshotter is containerd snapshotter for zfs
	ZFSSnapshotter = "zfs"
)

// ZVolName returns name of zvol for volume
func (status VolumeStatus) ZVolName() string {
	pool := VolumeClearZFSDataset
	if status.Encrypted {
		pool = VolumeEncryptedZFSDataset
	}
	return fmt.Sprintf("%s/%s.%d", pool, status.VolumeID.String(),
		status.GenerationCounter+status.LocalGenerationCounter)
}

// ZVolNameToKey returns key for volumestatus for provided zVolName
func ZVolNameToKey(zVolName string) string {
	split := strings.Split(zVolName, "/")
	lastPart := split[len(split)-1]
	return strings.ReplaceAll(lastPart, ".", "#")
}

// ZVolStatus specifies the needed information for zfs volume
type ZVolStatus struct {
	Dataset string
	Device  string
}

// Key is volume UUID which will be unique
func (status ZVolStatus) Key() string {
	return status.Device
}

// StorageRaidType indicates storage raid type
type StorageRaidType int32

// StorageRaidType enum should be in sync with info api
const (
	StorageRaidTypeUnspecified StorageRaidType = 0
	StorageRaidTypeRAID0       StorageRaidType = 1 // RAID-0
	StorageRaidTypeRAID1       StorageRaidType = 2 // Mirror
	StorageRaidTypeRAID5       StorageRaidType = 3 // raidz1 (RAID-5)
	StorageRaidTypeRAID6       StorageRaidType = 4 // raidz2 (RAID-6)
	StorageRaidTypeRAID7       StorageRaidType = 5 // raidz3 (RAID-7)
	StorageRaidTypeNoRAID      StorageRaidType = 6 // without RAID
)

// StorageStatus indicates current status of storage
type StorageStatus int32

// StorageStatus enum should be in sync with info api
const (
	StorageStatusUnspecified StorageStatus = 0
	StorageStatusOnline      StorageStatus = 1 // The device or virtual device is in normal working order.
	StorageStatusDegraded    StorageStatus = 2 // The virtual device has experienced a failure but can still function.
	StorageStatusFaulted     StorageStatus = 3 // The device or virtual device is completely inaccessible.
	StorageStatusOffline     StorageStatus = 4 // The device has been explicitly taken offline by the administrator.
	StorageStatusUnavail     StorageStatus = 5 // The device or virtual device cannot be opened. In some cases, pools with UNAVAIL devices appear in DEGRADED mode.
	StorageStatusRemoved     StorageStatus = 6 // The device was physically removed while the system was running.
	StorageStatusSuspended   StorageStatus = 7 // A pool that is waiting for device connectivity to be restored.
)

// ZFSPoolStatus stores collected information about zpool
type ZFSPoolStatus struct {
	PoolName         string
	ZfsVersion       string
	CurrentRaid      StorageRaidType
	CompressionRatio float64
	ZpoolSize        uint64
	CountZvols       uint32
	StorageState     StorageStatus
	Disks            []*StorageDiskState
	CollectorErrors  string
	Children         []*StorageChildren
}

//Key for pubsub
func (s ZFSPoolStatus) Key() string {
	return s.PoolName
}

// DiskDescription stores disk information
type DiskDescription struct {
	Name        string // bus-related name, for example: /dev/sdc
	LogicalName string // logical name, for example: disk3
	Serial      string // serial number of disk
}

//StorageDiskState represent state of disk
type StorageDiskState struct {
	DiskName *DiskDescription
	Status   StorageStatus
}

// StorageChildren stores children of zfs pool
type StorageChildren struct {
	CurrentRaid StorageRaidType
	Disks       []*StorageDiskState
	Children    []*StorageChildren
}
