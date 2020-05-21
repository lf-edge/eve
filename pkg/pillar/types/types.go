// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
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
	CREATING_VOLUME // Volume create in progress
	CREATED_VOLUME  // Volume create done or failed
	INSTALLED       // Available to be activated
	BOOTING
	RUNNING
	HALTING // being halted
	HALTED
	RESTARTING // Restarting due to config change or zcli
	PURGING    // Purging due to config change
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
	case CREATING_VOLUME:
		return "CREATING_VOLUME"
	case CREATED_VOLUME:
		return "CREATED_VOLUME"
	case INSTALLED:
		return "INSTALLED"
	case BOOTING:
		return "BOOTING"
	case RUNNING:
		return "RUNNING"
	case HALTING:
		return "HALTING"
	case HALTED:
		return "HALTED"
	case RESTARTING:
		return "RESTARTING"
	case PURGING:
		return "PURGING"
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
	case DOWNLOADED, VERIFYING:
		return info.ZSwState_DOWNLOADED
	case VERIFIED:
		return info.ZSwState_DELIVERED
	case CREATING_VOLUME:
		return info.ZSwState_CREATING_VOLUME
	case CREATED_VOLUME:
		return info.ZSwState_CREATED_VOLUME
	case INSTALLED:
		return info.ZSwState_INSTALLED
	case BOOTING:
		return info.ZSwState_BOOTING
	case RUNNING:
		return info.ZSwState_RUNNING
	case HALTING:
		return info.ZSwState_HALTING
	case HALTED:
		return info.ZSwState_HALTED
	case RESTARTING:
		return info.ZSwState_RESTARTING
	case PURGING:
		return info.ZSwState_PURGING
	default:
		log.Fatalf("Unknown state %d", state)
	}
	return info.ZSwState_INITIAL
}

// NoHash should XXX deprecate?
const (
	// NoHash constant to indicate that we have no real hash
	NoHash = "sha"
)

// UrlToSafename returns a safename
// XXX deprecate? We might need something for certs
func UrlToSafename(url string, sha string) string {

	var safename string

	if sha != "" {
		safename = strings.Replace(url, "/", " ", -1) + "." + sha
	} else {
		safename = strings.Replace(url, "/", " ", -1) + "." + NoHash
	}
	return safename
}

// SafenameToFilename returns the filename from inside the safename
// Remove initial part up to last '/' in URL. Note that '/' was converted
// to ' ' in Safename
// XXX deprecate? We might need something for certs
func SafenameToFilename(safename string) string {
	comp := strings.Split(safename, " ")
	last := comp[len(comp)-1]
	// Drop "."sha256 tail part of Safename
	i := strings.LastIndex(last, ".")
	if i == -1 {
		log.Fatal("Malformed safename with no .sha256",
			safename)
	}
	last = last[0:i]
	return last
}

// UrlToFilename returns the last component of a URL.
// XXX deprecate? We might need something for certs
// XXX assumes len
func UrlToFilename(urlName string) string {
	comp := strings.Split(urlName, "/")
	last := comp[len(comp)-1]
	return last
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

func (info UuidToNum) Key() string {
	return info.UUID.String()
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
		log.Fatalf("Invalid TriState Value: %v", state)
	}
	return ""
}
