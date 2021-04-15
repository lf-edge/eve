// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

type UsageZone int

const (
	GREEN_ZONE  UsageZone = 0
	YELLOW_ZONE UsageZone = 1
	ORANGE_ZONE UsageZone = 2
	RED_ZONE    UsageZone = 3
)

type MemoryNotification struct {
	Total uint64 // Total memory in Bytes
	Used  uint64 // Used memory in Bytes
	Zone  UsageZone

	PrevUsage uint64   // Previous (last) memory usage in Bytes
	LastFive  []uint64 // Last 5 Usage percentage values

	UsageSlab uint64
	PrevSlab  uint64
}

func zonetoString(zone UsageZone) string {
	switch zone {
	case GREEN_ZONE:
		return "GREEN"
	case YELLOW_ZONE:
		return "YELLOW"
	case ORANGE_ZONE:
		return "ORANGE"
	case RED_ZONE:
		return "RED"
	}
	return "UNKNOWN"
}

// LogCreate :
func (mem MemoryNotification) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.MemoryNotificationType, "MemoryNotification",
		uuid.UUID{}, mem.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("Total", mem.Total).
		CloneAndAddField("Used", mem.Used).
		CloneAndAddField("Zone", zonetoString(mem.Zone)).
		CloneAndAddField("PrevUsage", mem.PrevUsage).
		CloneAndAddField("LastFive", mem.LastFive).
		CloneAndAddField("UsageSlab", mem.UsageSlab).
		CloneAndAddField("PrevSlab", mem.PrevSlab).
		Noticef("MemoryNotification create")
}

// LogModify :
func (mem MemoryNotification) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.NewLogObject(logBase, base.MemoryNotificationType, "MemoryNotification",
		uuid.UUID{}, mem.LogKey())
	if logObject == nil {
		return
	}
	oldMem, ok := old.(MemoryNotification)
	if !ok {
		return
	}
	if mem.UsageSlab == oldMem.UsageSlab && mem.Zone == oldMem.Zone {
		return
	}
	logObject.CloneAndAddField("Total", mem.Total).
		CloneAndAddField("Used", mem.Used).
		CloneAndAddField("Zone", zonetoString(mem.Zone)).
		CloneAndAddField("PrevUsage", mem.PrevUsage).
		CloneAndAddField("LastFive", mem.LastFive).
		CloneAndAddField("UsageSlab", mem.UsageSlab).
		CloneAndAddField("PrevSlab", mem.PrevSlab).
		Noticef("MemoryNotification modify")
}

// LogDelete :
func (mem MemoryNotification) LogDelete(logBase *base.LogObject) {
}

// LogKey :
func (mem MemoryNotification) LogKey() string {
	return "MemoryNotification"
}

type DiskNotification struct {
	Total uint64 // Total Disk space in Bytes
	Used  uint64 // Used Disk space in Bytes
	Zone  UsageZone

	PrevUsage uint64   // Previous (last) disk usage in Bytes
	LastFive  []uint64 // Last 5 usage percentage values

	UsageSlab uint64
	PrevSlab  uint64
}

// LogCreate :
func (disk DiskNotification) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.DiskNotificationType, "DiskNotification",
		uuid.UUID{}, disk.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("Total", disk.Total).
		CloneAndAddField("Used", disk.Used).
		CloneAndAddField("Zone", zonetoString(disk.Zone)).
		CloneAndAddField("PrevUsage", disk.PrevUsage).
		CloneAndAddField("LastFive", disk.LastFive).
		CloneAndAddField("UsageSlab", disk.UsageSlab).
		CloneAndAddField("PrevSlab", disk.PrevSlab).
		Noticef("DiskNotification create")
}

// LogModify :
func (disk DiskNotification) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.NewLogObject(logBase, base.DiskNotificationType, "DiskNotification",
		uuid.UUID{}, disk.LogKey())
	if logObject == nil {
		return
	}
	oldDisk, ok := old.(DiskNotification)
	if !ok {
		return
	}
	if disk.UsageSlab == oldDisk.UsageSlab && disk.Zone == oldDisk.Zone {
		return
	}
	logObject.CloneAndAddField("Total", disk.Total).
		CloneAndAddField("Used", disk.Used).
		CloneAndAddField("Zone", zonetoString(disk.Zone)).
		CloneAndAddField("PrevUsage", disk.PrevUsage).
		CloneAndAddField("LastFive", disk.LastFive).
		CloneAndAddField("UsageSlab", disk.UsageSlab).
		CloneAndAddField("PrevSlab", disk.PrevSlab).
		Noticef("DiskNotification modify")
}

// LogDelete :
func (disk DiskNotification) LogDelete(logBase *base.LogObject) {
}

// LogKey :
func (disk DiskNotification) LogKey() string {
	return "DiskNotification"
}
