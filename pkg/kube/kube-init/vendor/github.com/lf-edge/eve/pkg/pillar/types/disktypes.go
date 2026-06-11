// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// EdgeNodeDiskDescription stores information to identify disk
type EdgeNodeDiskDescription struct {
	Name        string
	LogicalName string
	Serial      string
}

// EdgeNodeDisks stores expected layout of disks
type EdgeNodeDisks struct {
	Disks     []EdgeNodeDiskConfig
	ArrayType EdgeNodeDiskArrayType
	Children  []EdgeNodeDisks
}

// Key for pubsub
func (EdgeNodeDisks) Key() string {
	return "global"
}

// EdgeNodeDiskConfigType should be in sync with api
type EdgeNodeDiskConfigType int32

// enum should be in sync with api
const (
	EdgeNodeDiskConfigTypeUnspecified EdgeNodeDiskConfigType = iota // no configured, do nothing
	EdgeNodeDiskConfigTypeEveOs                                     // the disk EVE is installed on
	EdgeNodeDiskConfigTypePersist                                   // the disk is separate persist partition or disk, not zfs
	EdgeNodeDiskConfigTypeZfsOnline                                 // included in zfs and online
	EdgeNodeDiskConfigTypeZfsOffline                                // included in zfs and offline
	EdgeNodeDiskConfigTypeAppDirect                                 // for direct assignment
	EdgeNodeDiskConfigTypeUnused                                    // removed from zfs/app-direct
)

// EdgeNodeDiskArrayType should be in sync with api
type EdgeNodeDiskArrayType int32

// enum should be in sync with api
const (
	EdgeNodeDiskArrayTypeUnspecified EdgeNodeDiskArrayType = 0 // no configured
	EdgeNodeDiskArrayTypeRAID0       EdgeNodeDiskArrayType = 1 // stripe
	EdgeNodeDiskArrayTypeRAID1       EdgeNodeDiskArrayType = 2 // mirror
	EdgeNodeDiskArrayTypeRAID5       EdgeNodeDiskArrayType = 3 // raidz1
	EdgeNodeDiskArrayTypeRAID6       EdgeNodeDiskArrayType = 4 // raidz2
)

// EdgeNodeDiskConfig disk configuration
type EdgeNodeDiskConfig struct {
	Disk    EdgeNodeDiskDescription
	OldDisk *EdgeNodeDiskDescription
	Config  EdgeNodeDiskConfigType
}
