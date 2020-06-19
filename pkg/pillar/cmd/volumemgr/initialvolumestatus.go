// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle publishing the existing-at-boot VolumeStatus
// Published under "unknown" objType with refcount=0. Moved to
// other objType when there is a reference.

package volumemgr

import (
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Really a constant
var nilUUID = uuid.UUID{}

// parseAppRwVolumeName - Returns volumeDirname, volume uuid, generationCounter
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

// populateExistingVolumesFormat iterates over the directory and takes format
// from the name of the volume and prepares map of it
func populateExistingVolumesFormat(dirName string) {

	log.Infof("populateExistingVolumesFormat(%s)", dirName)
	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Errorf("populateExistingVolumesFormat: read directory '%s' failed: %v",
			dirName, err)
		return
	}
	for _, location := range locations {
		volumeName := strings.Split(location.Name(), ".")
		if len(volumeName) > 1 {
			volumeKey := volumeName[0]
			format := strings.ToUpper(volumeName[1])
			volumeFormat[volumeKey] = zconfig.Format(zconfig.Format_value[format])
		} else {
			log.Errorf("populateExistingVolumesFormat: Found bad volume %s in %s", location.Name(), dirName)
		}
	}
	log.Infof("populateExistingVolumesFormat(%s) Done", dirName)
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

	log.Debugf("gcObjects(%s)", dirName)
	locations, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Errorf("gcObjects: read directory '%s' failed: %v",
			dirName, err)
		return
	}
	for _, location := range locations {
		volumeName := strings.Split(location.Name(), ".")
		if len(volumeName) > 1 {
			volumeKey := volumeName[0]
			vs := lookupVolumeStatus(ctx, volumeKey)
			if vs == nil {
				log.Errorf("gcObjects: Found unused volume %s in %s. Deleting it.",
					location.Name(), dirName)
				deleteFile(path.Join(dirName, location.Name()))
			}
		} else {
			log.Errorf("gcObjects: Found bad volume %s in %s. Deleting it.",
				location.Name(), dirName)
			deleteFile(path.Join(dirName, location.Name()))
		}
	}
	log.Debugf("gcObjects(%s) Done", dirName)
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

func deleteFile(filelocation string) {
	if err := os.RemoveAll(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}
