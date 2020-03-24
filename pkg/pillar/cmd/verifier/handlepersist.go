// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handlers for PersistImageConfig

package verifier

import (
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Track the RefCount on the Persist object
func handlePersistCreate(ctx *verifierContext, objType string,
	config *types.PersistImageConfig) {

	log.Infof("handlePersistCreate(%s) objType %s for %s\n",
		config.ImageSha256, objType, config.Name)
	if objType == "" {
		log.Fatalf("handlePersistCreate: No ObjType for %s\n",
			config.ImageSha256)
	}
	// Require a status since we otherwise don't have a FileLocation
	status := lookupPersistImageStatus(ctx, objType, config.ImageSha256)
	if status == nil {
		log.Errorf("No PersistImageStatus but config for %s/%s",
			objType, config.ImageSha256)
		return
	}
	// Update
	status.Name = config.Name
	status.RefCount = config.RefCount
	status.LastUse = time.Now()
	publishPersistImageStatus(ctx, status)
	log.Infof("handlePersistCreate done for %s\n", config.Name)
}

// Track RefCount on persistent object
func handlePersistModify(ctx *verifierContext, config *types.PersistImageConfig,
	status *types.PersistImageStatus) {

	changed := false
	log.Infof("handlePersistModify(%s) objType %s for %s, config.RefCount: %d, "+
		"status.RefCount: %d",
		status.ImageSha256, status.ObjType, config.Name, config.RefCount,
		status.RefCount)

	if status.ObjType == "" {
		log.Fatalf("handlePersistModify: No ObjType for %s\n",
			status.ImageSha256)
	}

	// Always update RefCount
	if status.RefCount != config.RefCount {
		log.Infof("handlePersistModify RefCount change %s from %d to %d Expired %v\n",
			config.Name, status.RefCount, config.RefCount,
			status.Expired)
		status.RefCount = config.RefCount
		status.Expired = false
		changed = true
	}

	if status.RefCount == 0 {
		// GC timer will clean up by marking status Expired
		// and some point in time.
		// Then user (volumemgr) will delete config.
		status.LastUse = time.Now()
		changed = true
	}

	if changed {
		publishPersistImageStatus(ctx, status)
	}
	log.Infof("handlePersistModify done for %s. Status.RefCount=%d, Expired=%t",
		config.Name, status.RefCount, status.Expired)
}

func handlePersistDelete(ctx *verifierContext, status *types.PersistImageStatus) {

	log.Infof("handlePersistDelete(%s) objType %s refcount %d lastUse %v Expired %v\n",
		status.ImageSha256, status.ObjType, status.RefCount,
		status.LastUse, status.Expired)

	if status.ObjType == "" {
		log.Fatalf("handlePersistDelete: No ObjType for %s\n",
			status.ImageSha256)
	}

	// No more use for this image. Delete
	verifiedDirname := status.ImageDownloadDirName()
	_, err := os.Stat(verifiedDirname)
	if err == nil {
		if _, err := os.Stat(preserveFilename); err != nil {
			log.Infof("handlePersistDelete removing %s\n", verifiedDirname)
			if err := os.RemoveAll(verifiedDirname); err != nil {
				log.Fatal(err)
			}
		} else {
			log.Infof("handlePersistDelete preserving %s\n", verifiedDirname)
		}
	}

	unpublishPersistImageStatus(ctx, status)
	log.Infof("handlePersistDelete done for %s\n", status.ImageSha256)
}
