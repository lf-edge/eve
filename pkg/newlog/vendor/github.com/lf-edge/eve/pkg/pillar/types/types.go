// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus" // OK for logrus.Fatal
)

// SwState started with enum names from OMA-TS-LWM2M_SwMgmt-V1_0-20151201-C
// but now has many additions.
// They are in order of progression (except for the RESTARTING and PURGING ones)
// We map this to info.ZSwState
type SwState uint8

const (
	// INITIAL is 100 to be able to tell any confusion with ZSwState
	INITIAL       SwState = iota + 100 // Initial value
	RESOLVING_TAG                      // Resolving an image tag
	RESOLVED_TAG                       // Tag has been resolved or resolution failed
	DOWNLOADING
	DOWNLOADED
	VERIFYING
	VERIFIED
	LOADING
	LOADED
	CREATING_VOLUME // Volume create in progress
	CREATED_VOLUME  // Volume create done or failed
	INSTALLED       // Available to be activated
	AWAITNETWORKINSTANCE
	BOOTING
	RUNNING
	PAUSING
	PAUSED
	HALTING // being halted
	HALTED
	RESTARTING // Restarting due to config change or zcli
	PURGING    // Purging due to config change
	BROKEN     // Domain is still alive, but its device model has failed
	UNKNOWN    // State of the domain can't be determined
	MAXSTATE
)

// String returns the string name
func (state SwState) String() string {
	switch state {
	case INITIAL:
		return "INITIAL"
	case RESOLVING_TAG:
		return "RESOLVING_TAG"
	case RESOLVED_TAG:
		return "RESOLVED_TAG"
	case DOWNLOADING:
		return "DOWNLOADING"
	case DOWNLOADED:
		return "DOWNLOADED"
	case VERIFYING:
		return "VERIFYING"
	case VERIFIED:
		return "VERIFIED"
	case LOADING:
		return "LOADING"
	case LOADED:
		return "LOADED"
	case CREATING_VOLUME:
		return "CREATING_VOLUME"
	case CREATED_VOLUME:
		return "CREATED_VOLUME"
	case INSTALLED:
		return "INSTALLED"
	case AWAITNETWORKINSTANCE:
		return "AWAITNETWORKINSTANCE"
	case BOOTING:
		return "BOOTING"
	case RUNNING:
		return "RUNNING"
	case PAUSING:
		return "PAUSING"
	case PAUSED:
		return "PAUSED"
	case HALTING:
		return "HALTING"
	case HALTED:
		return "HALTED"
	case RESTARTING:
		return "RESTARTING"
	case PURGING:
		return "PURGING"
	case BROKEN:
		return "BROKEN"
	case UNKNOWN:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("Unknown state %d", state)
	}
}

// ZSwState returns different numbers and in some cases mapped many to one
func (state SwState) ZSwState() info.ZSwState {
	switch state {
	case 0:
		return 0
	case INITIAL:
		return info.ZSwState_INITIAL
	case RESOLVING_TAG:
		return info.ZSwState_RESOLVING_TAG
	case RESOLVED_TAG:
		return info.ZSwState_RESOLVED_TAG
	case DOWNLOADING:
		return info.ZSwState_DOWNLOAD_STARTED
	case DOWNLOADED:
		return info.ZSwState_DOWNLOADED
	case VERIFYING:
		return info.ZSwState_VERIFYING
	case VERIFIED:
		return info.ZSwState_VERIFIED
	case LOADING:
		return info.ZSwState_LOADING
	case LOADED:
		// TBD return info.ZSwState_LOADED
		return info.ZSwState_DELIVERED
	case CREATING_VOLUME:
		return info.ZSwState_CREATING_VOLUME
	case CREATED_VOLUME:
		return info.ZSwState_CREATED_VOLUME
	case INSTALLED:
		return info.ZSwState_INSTALLED
	case AWAITNETWORKINSTANCE:
		return info.ZSwState_AWAITNETWORKINSTANCE
	case BOOTING:
		return info.ZSwState_BOOTING
	case RUNNING:
		return info.ZSwState_RUNNING
	// for now we're treating PAUSING as a subset of RUNNING
	// simply because controllers don't support resumable
	// paused tasks yet
	case PAUSING:
		return info.ZSwState_RUNNING
	// for now we're treating PAUSED as a subset
	// of INSTALLED simply because controllers don't
	// support resumable paused tasks just yet (see
	// how PAUSING maps to RUNNING below)
	case PAUSED:
		return info.ZSwState_INSTALLED
	case HALTING:
		return info.ZSwState_HALTING
	case HALTED:
		return info.ZSwState_HALTED
	case RESTARTING:
		return info.ZSwState_RESTARTING
	case PURGING:
		return info.ZSwState_PURGING
	// we map BROKEN to HALTING to indicate that EVE has an active
	// role in reaping BROKEN domains and transitioning them to
	// a final HALTED state
	case BROKEN:
		return info.ZSwState_HALTING
	// If we ever see UNKNOWN we return RUNNING assuming the state will change to something
	// known soon.
	case UNKNOWN:
		return info.ZSwState_RUNNING
	default:
		logrus.Fatalf("Unknown state %d", state)
	}
	return info.ZSwState_INITIAL
}

// Used to retain UUID to integer maps across reboots.
// Used for appNum and bridgeNum
type UuidToNum struct {
	UUID        uuid.UUID
	Number      int
	NumType     string // For logging
	CreateTime  time.Time
	LastUseTime time.Time
	InUse       bool
}

// Key is the key in pubsub
func (info UuidToNum) Key() string {
	return info.UUID.String()
}

// LogCreate :
func (info UuidToNum) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.UUIDToNumLogType, "",
		info.UUID, info.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("UuidToNum info create")
}

// LogModify :
func (info UuidToNum) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.UUIDToNumLogType, "",
		info.UUID, info.LogKey())

	oldInfo, ok := old.(UuidToNum)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of UuidToNum type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldInfo, info)).
		Noticef("UuidToNum info modify")
}

// LogDelete :
func (info UuidToNum) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.UUIDToNumLogType, "",
		info.UUID, info.LogKey())
	logObject.Noticef("UuidToNum info delete")

	base.DeleteLogObject(logBase, info.LogKey())
}

// LogKey :
func (info UuidToNum) LogKey() string {
	return string(base.UUIDToNumLogType) + "-" + info.Key()
}

// Use this for booleans which have a none/dontcare/notset value
type TriState uint8

const (
	TS_NONE TriState = iota
	TS_DISABLED
	TS_ENABLED
)

func ParseTriState(value string) (TriState, error) {
	var ts TriState

	switch value {
	case "none":
		ts = TS_NONE
	case "enabled", "enable", "on":
		ts = TS_ENABLED
	case "disabled", "disable", "off":
		ts = TS_DISABLED
	default:
		err := errors.New(fmt.Sprintf("Bad value: %s", value))
		return ts, err
	}
	return ts, nil
}

// FormatTriState - return string format of TriState
func FormatTriState(state TriState) string {
	switch state {
	case TS_NONE:
		return "none"
	case TS_ENABLED:
		return "enabled"
	case TS_DISABLED:
		return "disabled"
	default:
		logrus.Fatalf("Invalid TriState Value: %v", state)
	}
	return ""
}

//UEvent stores information about uevent comes from kernel
type UEvent struct {
	Action string
	Obj    string
	Env    map[string]string
}
