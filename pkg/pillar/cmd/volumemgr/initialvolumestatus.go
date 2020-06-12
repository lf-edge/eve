// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle publishing the existing-at-boot VolumeStatus
// Published under "unknown" objType with refcount=0. Moved to
// other objType when there is a reference.

package volumemgr

import (
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
	log "github.com/sirupsen/logrus"
)

// Really a constant
var nilUUID = uuid.UUID{}

// parseAppRwVolumeName - Returns rwImgDirname, volume uuid, generationCounter
func parseAppRwVolumeName(image string) (string, string, uint32) {
	re1 := regexp.MustCompile(`(.+)/([0-9a-fA-F\-]+)#([0-9]+)`)
	if !re1.MatchString(image) {
		log.Errorf("AppRwVolumeName %s doesn't match pattern", image)
		return "", "", 0
	}
	parsedStrings := re1.FindStringSubmatch(image)
	count, err := strconv.ParseUint(parsedStrings[3], 10, 32)
	if err != nil {
		log.Error(err)
		count = 0
	}
	return parsedStrings[1], parsedStrings[2], uint32(count)
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
		_, volumeID, generationCounter := parseAppRwVolumeName(filelocation)
		log.Infof("populateInitialVolumeStatus: Processing volume uuid: %s, fileLocation:%s",
			volumeID, filelocation)

		volumeUUID, err := uuid.FromString(volumeID)
		if err != nil {
			log.Errorf("populateInitialVolumeStatus: Invalid volume UUIDStr(%s) in "+
				"filename (%s). err: %s. XXX ignoring the File",
				volumeID, filelocation, err)
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
	pub := ctx.pubUnknownVolumeStatus
	pub.Publish(key, *status)
	log.Debugf("publishInitialVolumeStatus(%s) Done", key)
}

func unpublishInitialVolumeStatus(ctx *volumemgrContext, volumeKey string) {

	pub := ctx.pubUnknownVolumeStatus
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
	pub := ctx.pubUnknownVolumeStatus
	st, _ := pub.Get(volumeKey)
	if st == nil {
		log.Infof("lookupInitVolumeStatus(%s) key not found", volumeKey)
		return nil
	}
	status := st.(types.VolumeStatus)
	return &status
}

// Periodic garbage collection looking at RefCount=0 files in the unknown
// Others have their delete handler.
func gcObjects(ctx *volumemgrContext, dirName string) {

	log.Debugf("gcObjects()")

	pub := ctx.pubUnknownVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.RefCount != 0 {
			log.Debugf("gcObjects: skipping RefCount %d: %s",
				status.RefCount, status.Key())
			continue
		}
		timePassed := time.Since(status.LastUse)
		timeLimit := time.Duration(ctx.vdiskGCTime) * time.Second
		if timePassed < timeLimit {
			log.Debugf("gcObjects: skipping recently used %s remains %d seconds",
				status.Key(), (timePassed-timeLimit)/time.Second)
			continue
		}
		filelocation := status.FileLocation
		if filelocation == "" {
			log.Errorf("No filelocation to remove for %s", status.Key())
		} else {
			log.Infof("gcObjects: removing %s LastUse %v now %v: %s",
				filelocation, status.LastUse, time.Now(), status.Key())
			if err := os.Remove(filelocation); err != nil {
				log.Errorln(err)
			}
		}
		unpublishInitialVolumeStatus(ctx, status.Key())
	}
}

// If an object has a zero RefCount and dropped to zero more than
// downloadGCTime ago, then we delete the Status. That will result in the
// verifier deleting the verified file
// XXX Note that this runs concurrently with the handler.
func gcVerifiedObjects(ctx *volumemgrContext) {
	log.Debugf("gcVerifiedObjects()")
	publications := []pubsub.Publication{
		ctx.pubAppImgPersistStatus,
		ctx.pubBaseOsPersistStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.PersistImageStatus)
			if status.RefCount != 0 {
				log.Debugf("gcVerifiedObjects: skipping RefCount %d: %s",
					status.RefCount, status.Key())
				continue
			}
			timePassed := time.Since(status.LastUse)
			if timePassed < downloadGCTime {
				log.Debugf("gcverifiedObjects: skipping recently used %s remains %d seconds",
					status.Key(),
					(timePassed-downloadGCTime)/time.Second)
				continue
			}
			log.Infof("gcVerifiedObjects: expiring status for %s; LastUse %v now %v",
				status.Key(), status.LastUse, time.Now())
			unpublishPersistImageStatus(ctx, &status)
		}
	}
}

// gc timer just started, reset the LastUse timestamp to now if the refcount is zero
func gcResetPersistObjectLastUse(ctx *volumemgrContext) {
	publications := []pubsub.Publication{
		ctx.pubAppImgPersistStatus,
		ctx.pubBaseOsPersistStatus,
	}
	for _, pub := range publications {
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.PersistImageStatus)
			if status.RefCount == 0 {
				status.LastUse = time.Now()
				log.Infof("gcResetPersistObjectLastUse: reset %v LastUse to now", status.Key())
				publishPersistImageStatus(ctx, &status)
			}
		}
	}
}

// gc timer just started, reset the LastUse timestamp
func gcResetObjectsLastUse(ctx *volumemgrContext, dirName string) {
	log.Debugf("gcResetObjectsLastUse()")
	pub := ctx.pubUnknownVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.RefCount == 0 {
			log.Infof("gcResetObjectsLastUse: reset %v LastUse to now", status.Key())
			status.LastUse = time.Now()
			publishInitialVolumeStatus(ctx, &status)
		}
	}
}

func deleteFile(filelocation string) {
	if err := os.RemoveAll(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}
