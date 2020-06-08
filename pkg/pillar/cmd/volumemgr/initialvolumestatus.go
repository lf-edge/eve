// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle publishing the existing-at-boot VolumeStatus
// Published under "unknown" objType with refcount=0. Moved to
// other objType when there is a reference.

package volumemgr

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
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

// Really a constant
var nilUUID = uuid.UUID{}

// appRwOldVolumeName - Returns name of the image ( including parent dir )
// Note that we still use the sha in the filename to not impact running images. Otherwise
// we could switch this to imageID
// XXX other types of volumes might want a different name.
func appRwOldVolumeName(sha256, uuidStr string, purgeCounter uint32, format zconfig.Format,
	origin types.OriginType, isContainer bool) string {

	purgeString := ""
	if purgeCounter != 0 {
		purgeString = fmt.Sprintf("#%d", purgeCounter)
	}
	if isContainer {
		return fmt.Sprintf("%s-%s%s", sha256, uuidStr, purgeString)
	}
	if origin != types.OriginTypeDownload {
		log.Fatalf("XXX unsupported origin %v", origin)
	}
	formatStr := strings.ToLower(format.String())
	return fmt.Sprintf("%s/%s-%s%s.%s", rwImgDirname, sha256,
		uuidStr, purgeString, formatStr)
}

// parseAppRwOldVolumeName - Returns rwImgDirname, sha256, uuidStr, purgeCounter
func parseAppRwOldVolumeName(image string, isContainer bool) (string, string, string, uint32) {
	// VolumeSha is provided by the controller - it can be uppercase
	// or lowercase.
	var re1 *regexp.Regexp
	var re2 *regexp.Regexp
	if isContainer {
		re1 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)#([0-9]+)`)
	} else {
		re1 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)#([0-9]+)\.(.+)`)
	}
	if re1.MatchString(image) {
		// With purgeCounter
		parsedStrings := re1.FindStringSubmatch(image)
		count, err := strconv.ParseUint(parsedStrings[4], 10, 32)
		if err != nil {
			log.Error(err)
			count = 0
		}
		return parsedStrings[1], parsedStrings[2], parsedStrings[3],
			uint32(count)
	}
	// Without purgeCounter
	if isContainer {
		re2 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)`)
	} else {
		re2 = regexp.MustCompile(`(.+)/([0-9A-Fa-f]+)-([0-9a-fA-F\-]+)\.([^\.]+)`)
	}
	if !re2.MatchString(image) {
		log.Errorf("AppRwOldVolumeName %s doesn't match pattern", image)
		return "", "", "", 0
	}
	parsedStrings := re2.FindStringSubmatch(image)
	return parsedStrings[1], parsedStrings[2], parsedStrings[3], 0
}

// recursive scanning for verified objects,
// to recreate the status files
func populateInitialOldVolumeStatus(ctx *volumemgrContext, dirName string) {

	log.Infof("populateInitialOldVolumeStatus(%s)", dirName)
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
		log.Errorf("populateInitialOldVolumeStatus: read directory '%s' failed: %v",
			dirName, err)
		return
	}

	for _, location := range locations {
		filelocation := dirName + "/" + location.Name()
		if location.IsDir() && !isContainer {
			log.Debugf("populateInitialOldVolumeStatus: directory %s ignored", filelocation)
			continue
		}
		info, err := os.Stat(filelocation)
		if err != nil {
			log.Errorf("Error in getting file information. Err: %s. "+
				"Deleting file %s", err, filelocation)
			deleteFile(filelocation)
			continue
		}
		_, sha256, appUUIDStr, purgeCounter := parseAppRwOldVolumeName(filelocation, isContainer)
		log.Infof("populateInitialOldVolumeStatus: Processing sha256: %s, AppUuid: %s, "+
			"fileLocation:%s",
			sha256, appUUIDStr, filelocation)

		appUUID, err := uuid.FromString(appUUIDStr)
		if err != nil {
			log.Errorf("populateInitialOldVolumeStatus: Invalid UUIDStr(%s) in "+
				"filename (%s). err: %s. Deleting the File",
				appUUIDStr, filelocation, err)
			deleteFile(filelocation)
			continue
		}

		status := types.OldVolumeStatus{
			BlobSha256:    sha256,
			AppInstID:     appUUID,
			VolumeID:      nilUUID, // XXX known for other origins?
			PurgeCounter:  purgeCounter,
			DisplayName:   "Found in /persist/img",
			FileLocation:  filelocation,
			State:         types.CREATED_VOLUME,
			ObjType:       types.UnknownObj,
			VolumeCreated: true,
			RefCount:      0,
			LastUse:       info.ModTime(),
			PreReboot:     info.ModTime().Before(deviceBootTime),
		}

		publishOldVolumeStatus(ctx, &status)
	}
}

// Remove from OldVolumeStatus since fileLocation has been deleted
// XXX implement and call.
func unpublishInitialOldVolumeStatus(ctx *volumemgrContext, volumeKey string) {

	pub := ctx.publication(types.OldVolumeStatus{}, types.UnknownObj)
	st, _ := pub.Get(volumeKey)
	if st == nil {
		log.Errorf("unpublishInitialOldVolumeStatus(%s) key not found",
			volumeKey)
		return
	}
	pub.Unpublish(volumeKey)
}

// XXX for now only handle those with a sha and appInstID
// XXX format arg is not used
func lookupInitOldVolumeStatus(ctx *volumemgrContext, volumeKey string, originType types.OriginType, format zconfig.Format) *types.OldVolumeStatus {

	log.Infof("lookupInitOldVolumeStatus(%s) type %d format %d", volumeKey,
		originType, format)
	// XXX for now
	if originType != types.OriginTypeDownload {
		return nil
	}
	// XXX do we need these check or just look up on volumeKey
	blobSha256, appInstID, volumeID, purgeCounter, err := types.VolumeKeyToParts(volumeKey)
	if err != nil {
		log.Errorf("lookupInitOldVolumeStatus failed: err %s", err)
		return nil
	}
	// XXX debug
	log.Infof("lookupInitOldVolumeStatus sha %s appinst %s volume %s purgeCounter %d",
		blobSha256, appInstID, volumeID, purgeCounter)
	if blobSha256 == "" {
		log.Infof("lookupInitOldVolumeStatus(%s) no sha; not found", volumeKey)
		return nil
	}
	if appInstID == nilUUID {
		log.Infof("lookupInitOldVolumeStatus(%s) no appInstID; not found", volumeKey)
		return nil
	}
	pub := ctx.publication(types.OldVolumeStatus{}, types.UnknownObj)
	st, _ := pub.Get(volumeKey)
	if st == nil {
		log.Infof("lookupInitOldVolumeStatus(%s) key not found", volumeKey)
		return nil
	}
	status := st.(types.OldVolumeStatus)
	return &status
}

// Periodic garbage collection looking at RefCount=0 files in the unknown
// Others have their delete handler.
func gcOldObjects(ctx *volumemgrContext, dirName string) {

	log.Debugf("gcOldObjects()")

	pub := ctx.publication(types.OldVolumeStatus{}, types.UnknownObj)
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.OldVolumeStatus)
		if status.RefCount != 0 {
			log.Debugf("gcOldObjects: skipping RefCount %d: %s",
				status.RefCount, status.Key())
			continue
		}
		timePassed := time.Since(status.LastUse)
		timeLimit := time.Duration(ctx.vdiskGCTime) * time.Second
		if timePassed < timeLimit {
			log.Debugf("gcOldObjects: skipping recently used %s remains %d seconds",
				status.Key(), (timePassed-timeLimit)/time.Second)
			continue
		}
		filelocation := status.FileLocation
		if filelocation == "" {
			log.Errorf("No filelocation to remove for %s", status.Key())
		} else {
			log.Infof("gcOldObjects: removing %s LastUse %v now %v: %s",
				filelocation, status.LastUse, time.Now(), status.Key())
			if err := os.Remove(filelocation); err != nil {
				log.Errorln(err)
			}
		}
		unpublishOldVolumeStatus(ctx, &status)
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

	pub := ctx.publication(types.OldVolumeStatus{}, types.UnknownObj)
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.OldVolumeStatus)
		if status.RefCount == 0 {
			log.Infof("gcResetObjectsLastUse: reset %v LastUse to now", status.Key())
			status.LastUse = time.Now()
			publishOldVolumeStatus(ctx, &status)
		}
	}
}

func deleteFile(filelocation string) {
	if err := os.RemoveAll(filelocation); err != nil {
		log.Errorf("Failed to delete file %s. Error: %s",
			filelocation, err.Error())
	}
}
