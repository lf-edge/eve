// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// UsageZone :
type UsageZone int

const (
	// GreenZone :
	GreenZone UsageZone = 0
	// YellowZone :
	YellowZone UsageZone = 1
	// OrangeZone :
	OrangeZone UsageZone = 2
	// RedZone :
	RedZone UsageZone = 3
)

// MemoryNotification :
type MemoryNotification struct {
	Total uint64 // Total memory in Bytes
	Used  uint64 // Used memory in Bytes
	Zone  UsageZone

	PrevUsage uint64 // Previous (last) memory usage in Bytes

	// Last 5 Usage percentage values
	// Most recent usage is at index 0, the next at index 1 and so on.
	LastFive []uint64

	UsageSlab uint64
	PrevSlab  uint64
}

func zonetoString(zone UsageZone) string {
	switch zone {
	case GreenZone:
		return "GREEN"
	case YellowZone:
		return "YELLOW"
	case OrangeZone:
		return "ORANGE"
	case RedZone:
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
	loggable := logObject.CloneAndAddField("Total", mem.Total).
		CloneAndAddField("Used", mem.Used).
		CloneAndAddField("Zone", zonetoString(mem.Zone)).
		CloneAndAddField("PrevUsage", mem.PrevUsage).
		CloneAndAddField("LastFive", mem.LastFive).
		CloneAndAddField("UsageSlab", mem.UsageSlab).
		CloneAndAddField("PrevSlab", mem.PrevSlab)
	switch mem.Zone {
	case GreenZone, YellowZone:
		loggable.Functionf("MemoryNotification create")
	case OrangeZone:
		loggable.Warnf("MemoryNotification create")
	case RedZone:
		loggable.Errorf("MemoryNotification create")
	default:
		loggable.Noticef("MemoryNotification create")
	}
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
	loggable := logObject.CloneAndAddField("Total", mem.Total).
		CloneAndAddField("Used", mem.Used).
		CloneAndAddField("Zone", zonetoString(mem.Zone)).
		CloneAndAddField("PrevUsage", mem.PrevUsage).
		CloneAndAddField("LastFive", mem.LastFive).
		CloneAndAddField("UsageSlab", mem.UsageSlab).
		CloneAndAddField("PrevSlab", mem.PrevSlab)
	switch mem.Zone {
	case GreenZone, YellowZone:
		loggable.Functionf("MemoryNotification create")
	case OrangeZone:
		loggable.Warnf("MemoryNotification create")
	case RedZone:
		loggable.Errorf("MemoryNotification create")
	default:
		loggable.Noticef("MemoryNotification create")
	}
}

// LogDelete :
func (mem MemoryNotification) LogDelete(logBase *base.LogObject) {
}

// LogKey :
func (mem MemoryNotification) LogKey() string {
	return "MemoryNotification"
}

// DiskNotification :
type DiskNotification struct {
	Total uint64 // Total Disk space in Bytes
	Used  uint64 // Used Disk space in Bytes
	Zone  UsageZone

	PrevUsage uint64 // Previous (last) disk usage in Bytes

	// Last 5 Usage percentage values
	// Most recent usage is at index 0, the next at index 1 and so on.
	LastFive []uint64

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
	loggable := logObject.CloneAndAddField("Total", disk.Total).
		CloneAndAddField("Used", disk.Used).
		CloneAndAddField("Zone", zonetoString(disk.Zone)).
		CloneAndAddField("PrevUsage", disk.PrevUsage).
		CloneAndAddField("LastFive", disk.LastFive).
		CloneAndAddField("UsageSlab", disk.UsageSlab).
		CloneAndAddField("PrevSlab", disk.PrevSlab)
	switch disk.Zone {
	case GreenZone, YellowZone:
		loggable.Functionf("DiskNotification create")
	case OrangeZone:
		loggable.Warnf("DiskNotification create")
	case RedZone:
		loggable.Errorf("DiskNotification create")
	default:
		loggable.Noticef("DiskNotification create")
	}
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
	loggable := logObject.CloneAndAddField("Total", disk.Total).
		CloneAndAddField("Used", disk.Used).
		CloneAndAddField("Zone", zonetoString(disk.Zone)).
		CloneAndAddField("PrevUsage", disk.PrevUsage).
		CloneAndAddField("LastFive", disk.LastFive).
		CloneAndAddField("UsageSlab", disk.UsageSlab).
		CloneAndAddField("PrevSlab", disk.PrevSlab)
	switch disk.Zone {
	case GreenZone, YellowZone:
		loggable.Functionf("DiskNotification create")
	case OrangeZone:
		loggable.Warnf("DiskNotification create")
	case RedZone:
		loggable.Errorf("DiskNotification create")
	default:
		loggable.Noticef("DiskNotification create")
	}
}

// LogDelete :
func (disk DiskNotification) LogDelete(logBase *base.LogObject) {
}

// LogKey :
func (disk DiskNotification) LogKey() string {
	return "DiskNotification"
}
