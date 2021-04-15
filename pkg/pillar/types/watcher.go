// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
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

// LogCreate :
func (mem MemoryNotification) LogCreate(logBase *base.LogObject) {
}

// LogModify :
func (mem MemoryNotification) LogModify(logBase *base.LogObject, old interface{}) {
}

// LogDelete :
func (mem MemoryNotification) LogDelete(logBase *base.LogObject) {
}

// LogKey :
func (mem MemoryNotification) LogKey() string {
	return ""
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
}

// LogModify :
func (disk DiskNotification) LogModify(logBase *base.LogObject, old interface{}) {
}

// LogDelete :
func (disk DiskNotification) LogDelete(logBase *base.LogObject) {
}

// LogKey :
func (disk DiskNotification) LogKey() string {
	return ""
}
