// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

// Look for old VM and OCI volumes in /persist

import (
	"os"
	"time"

	uuid "github.com/satori/go.uuid"
)

// We fill in this based on the files/dirs we find on disk
type oldVolume struct {
	pathname     string
	sha256       string
	appInstID    uuid.UUID
	purgeCounter uint32
	format       string
	modTime      time.Time // If we have multiple we pick latest
}

// recursive scanning for volumes
func scanDir(dirName string, isContainer bool) []oldVolume {

	log.Tracef("scanDir(%s)", dirName)
	var old []oldVolume

	locations, err := os.ReadDir(dirName)
	if err != nil {
		log.Errorf("scanDir: read directory '%s' failed: %v",
			dirName, err)
		return old
	}

	for _, location := range locations {
		filelocation := dirName + "/" + location.Name()
		if location.IsDir() && !isContainer {
			log.Tracef("scanDir: directory %s ignored", filelocation)
			continue
		}
		info, err := os.Stat(filelocation)
		if err != nil {
			log.Errorf("Error in getting file information. Err: %s. "+
				"Ignoring file %s", err, filelocation)
			continue
		}
		_, sha256, appUUIDStr, purgeCounter, format := parseAppRwVolumeName(filelocation, isContainer)
		log.Functionf("scanDir: Processing sha256: %s, AppUuid: %s, "+
			"fileLocation:%s, format:%s",
			sha256, appUUIDStr, filelocation, format)

		appUUID, err := uuid.FromString(appUUIDStr)
		if err != nil {
			log.Errorf("scanDir: Invalid UUIDStr(%s) in "+
				"filename (%s). err: %s. Ignored",
				appUUIDStr, filelocation, err)
			continue
		}
		item := oldVolume{
			sha256:       sha256,
			appInstID:    appUUID,
			purgeCounter: purgeCounter,
			format:       format,
			pathname:     filelocation,
			modTime:      info.ModTime(),
		}
		old = append(old, item)
	}
	return old
}
