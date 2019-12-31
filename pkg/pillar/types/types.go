// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Enum names from OMA-TS-LWM2M_SwMgmt-V1_0-20151201-C
// The ones starting with BOOTING are in addition to OMA and represent
// operational/activated states.
type SwState uint8

const (
	INITIAL          SwState = iota + 1
	DOWNLOAD_STARTED         // Really download in progress
	DOWNLOADED
	DELIVERED // Package integrity verified
	INSTALLED // Available to be activated
	BOOTING
	RUNNING
	HALTING // being halted
	HALTED
	RESTARTING // Restarting due to config change or zcli
	PURGING    // Purging due to config change
	MAXSTATE   //
)

const (
	// NoHash constant to indicate that we have no real hash
	NoHash = "sha"
)

func UrlToSafename(url string, sha string) string {

	var safename string

	if sha != "" {
		safename = strings.Replace(url, "/", " ", -1) + "." + sha
	} else {
		safename = strings.Replace(url, "/", " ", -1) + "." + NoHash
	}
	return safename
}

// Remove initial part up to last '/' in URL. Note that '/' was converted
// to ' ' in Safename
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
