// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ExtsloaderState represents the state of the extension services loader
type ExtsloaderState uint8

const (
	// ExtsloaderStateStarting - extsloader is initializing
	ExtsloaderStateStarting ExtsloaderState = iota
	// ExtsloaderStateReady - Extension mounted and services starting
	ExtsloaderStateReady
	// ExtsloaderStateFailed - Extension loading failed
	ExtsloaderStateFailed
)

func (s ExtsloaderState) String() string {
	switch s {
	case ExtsloaderStateStarting:
		return "starting"
	case ExtsloaderStateReady:
		return "ready"
	case ExtsloaderStateFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// ExtsloaderStatus represents the status of the Extension services loader.
// Published by extsloader, consumed by nodeagent for update testing validation.
type ExtsloaderStatus struct {
	// State is the current loader state
	State ExtsloaderState
	// Reason describes why the loader is in failed state (empty if ready)
	Reason string
	// Partition is the active partition label (IMGA/IMGB)
	Partition string
	// ImagePath is the path to the Extension image on persist
	ImagePath string
	// MountPoint is where the Extension is mounted
	MountPoint string
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key returns the pubsub key for ExtsloaderStatus (singleton)
func (status ExtsloaderStatus) Key() string {
	return "global"
}

// LogCreate logs the creation of ExtsloaderStatus
func (status ExtsloaderStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ExtsloaderStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Extsloader status create: state=%s partition=%s",
		status.State, status.Partition)
}

// LogModify logs modifications to ExtsloaderStatus
func (status ExtsloaderStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ExtsloaderStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Extsloader status modify: state=%s partition=%s reason=%s",
		status.State, status.Partition, status.Reason)
}

// LogDelete logs deletion of ExtsloaderStatus
func (status ExtsloaderStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ExtsloaderStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Extsloader status delete")
	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey returns the key for log object
func (status ExtsloaderStatus) LogKey() string {
	return "extsloader-status"
}
