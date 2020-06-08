// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle publishing the existing-at-boot VolumeStatus
// Published under "unknown" objType.

package volumemgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
	log "github.com/sirupsen/logrus"
)

// appRwVolumeName - Returns name of the image ( including parent dir )
func appRwVolumeName(uuidStr string, generationCounter uint32,
	format zconfig.Format, isContainer bool) string {

	purgeString := ""
	if generationCounter != 0 {
		purgeString = fmt.Sprintf("#%d", generationCounter)
	}
	if isContainer {
		return fmt.Sprintf("%s%s", uuidStr, purgeString)
	}
	formatStr := strings.ToLower(format.String())
	return fmt.Sprintf("%s/%s%s.%s", rwImgDirname,
		uuidStr, purgeString, formatStr)
}

// parseAppRwVolumeName - Returns rwImgDirname, volume uuid, generationCounter
func parseAppRwVolumeName(image string, isContainer bool) (string, string, uint32) {
	// VolumeSha is provided by the controller - it can be uppercase
	// or lowercase.
	var re1 *regexp.Regexp
	var re2 *regexp.Regexp
	if isContainer {
		re1 = regexp.MustCompile(`(.+)/([0-9a-fA-F\-]+)#([0-9]+)`)
	} else {
		re1 = regexp.MustCompile(`(.+)/([0-9a-fA-F\-]+)#([0-9]+)\.(.+)`)
	}
	if re1.MatchString(image) {
		// With purgeCounter
		parsedStrings := re1.FindStringSubmatch(image)
		count, err := strconv.ParseUint(parsedStrings[3], 10, 32)
		if err != nil {
			log.Error(err)
			count = 0
		}
		return parsedStrings[1], parsedStrings[2], uint32(count)
	}
	// Without purgeCounter
	if isContainer {
		re2 = regexp.MustCompile(`(.+)/([0-9a-fA-F\-]+)`)
	} else {
		re2 = regexp.MustCompile(`(.+)/([0-9a-fA-F\-]+)\.([^\.]+)`)
	}
	if !re2.MatchString(image) {
		log.Errorf("AppRwVolumeName %s doesn't match pattern", image)
		return "", "", 0
	}
	parsedStrings := re2.FindStringSubmatch(image)
	return parsedStrings[1], parsedStrings[2], 0
}

// recursive scanning for verified objects,
// to recreate the status files
func populateInitialVolumeStatus(ctx *volumemgrContext, dirName string) {

	log.Infof("populateInitialVolumeStatus(%s)", dirName)
	var isContainer bool
	if dirName == rwImgDirname {
		isContainer = false
	} else if dirName == roContImgDirname {
		isContainer = true
	}

	// Record host boot time for comparisons
	hinfo, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s", err)
	}
	deviceBootTime := time.Unix(int64(hinfo.BootTime), 0).UTC()

	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Errorf("populateInitialVolumeStatus: read directory '%s' failed: %v",
			dirName, err)
		return
	}

	for _, location := range locations {
		filelocation := dirName + "/" + location.Name()
		if location.IsDir() && !isContainer {
			log.Debugf("populateInitialVolumeStatus: directory %s ignored", filelocation)
			continue
		}
		info, err := os.Stat(filelocation)
		if err != nil {
			log.Errorf("Error in getting file information. Err: %s. "+
				"Deleting file %s", err, filelocation)
			deleteFile(filelocation)
			continue
		}
		_, volumeID, generationCounter := parseAppRwVolumeName(filelocation, isContainer)
		log.Infof("populateInitialVolumeStatus: Processing volume uuid: %s, fileLocation:%s",
			volumeID, filelocation)

		volumeUUID, err := uuid.FromString(volumeID)
		if err != nil {
			log.Errorf("populateInitialVolumeStatus: Invalid volume UUIDStr(%s) in "+
				"filename (%s). err: %s. Deleting the File",
				volumeID, filelocation, err)
			deleteFile(filelocation)
			continue
		}

		status := types.VolumeStatus{
			VolumeID:          volumeUUID,
			GenerationCounter: int64(generationCounter),
			DisplayName:       "Found in /persist/img",
			FileLocation:      filelocation,
			State:             types.CREATED_VOLUME,
			VolumeCreated:     true,
			LastUse:           info.ModTime(),
			PreReboot:         info.ModTime().Before(deviceBootTime),
		}

		publishInitialVolumeStatus(ctx, &status)
	}
}

func publishInitialVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	key := status.Key()
	log.Debugf("publishInitialVolumeStatus(%s)", key)
	pub := ctx.pubUnknownNewVolumeStatus
	pub.Publish(key, *status)
	log.Debugf("publishInitialVolumeStatus(%s) Done", key)
}

func unpublishInitialVolumeStatus(ctx *volumemgrContext, volumeKey string) {

	pub := ctx.pubUnknownNewVolumeStatus
	st, _ := pub.Get(volumeKey)
	if st == nil {
		log.Errorf("unpublishInitialVolumeStatus(%s) key not found",
			volumeKey)
		return
	}
	pub.Unpublish(volumeKey)
}

func lookupInitVolumeStatus(ctx *volumemgrContext, volumeKey string) *types.VolumeStatus {

	log.Infof("lookupInitVolumeStatus for %s", volumeKey)
	pub := ctx.pubUnknownNewVolumeStatus
	st, _ := pub.Get(volumeKey)
	if st == nil {
		log.Infof("lookupInitVolumeStatus(%s) key not found", volumeKey)
		return nil
	}
	status := st.(types.VolumeStatus)
	return &status
}
