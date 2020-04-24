// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Interact with the persistent mapping from AppUUID, ImageID to sha of the
// image

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Add or update
func addAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID, imageID uuid.UUID,
	hash string, purgeCounter uint32) {

	log.Infof("addAppAndImageHash(%s, %s, %s, %d)", appUUID, imageID, hash, purgeCounter)
	if hash == "" {
		log.Errorf("addAppAndImageHash(%s, %s, %d) empty hash",
			appUUID, imageID, purgeCounter)
		return
	}
	aih := types.AppAndImageToHash{
		AppUUID:      appUUID,
		ImageID:      imageID,
		Hash:         hash,
		PurgeCounter: purgeCounter,
	}
	item, _ := ctx.pubAppAndImageToHash.Get(aih.Key())
	if item != nil {
		old := item.(types.AppAndImageToHash)
		if old.Hash == aih.Hash {
			log.Warnf("addAppAndImageHash(%s, %s, %d) no change %s",
				appUUID, imageID, purgeCounter, old.Hash)
			return
		}
		log.Warnf("addAppAndImageHash(%s, %s, %d) change from %s to %s",
			appUUID, imageID, purgeCounter, old.Hash, aih.Hash)
	}
	ctx.pubAppAndImageToHash.Publish(aih.Key(), aih)
	log.Infof("addAppAndImageHash(%s, %s, %s, %d) done", appUUID, imageID, hash, purgeCounter)
}

// Delete for a specific image
func deleteAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID,
	imageID uuid.UUID, purgeCounter uint32) {

	log.Infof("deleteAppAndImageHash(%s, %s, %d)", appUUID, imageID, purgeCounter)
	aih := types.AppAndImageToHash{
		AppUUID:      appUUID,
		ImageID:      imageID,
		PurgeCounter: purgeCounter,
	}
	item, _ := ctx.pubAppAndImageToHash.Get(aih.Key())
	if item == nil {
		log.Errorf("deleteAppAndImageHash(%s, %s, %d) not found",
			appUUID, imageID, purgeCounter)
		return
	}
	ctx.pubAppAndImageToHash.Unpublish(aih.Key())
	log.Infof("deleteAppAndImageHash(%s, %s, %d) done", appUUID, imageID, purgeCounter)
}

// Purge all for appUUID
func purgeAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID) {

	log.Infof("purgeAppAndImageHash(%s)", appUUID)
	items := ctx.pubAppAndImageToHash.GetAll()
	for _, a := range items {
		aih := a.(types.AppAndImageToHash)
		if aih.AppUUID == appUUID {
			log.Errorf("purgeAppAndImageHash(%s) deleting %s hash %s",
				appUUID, aih.ImageID, aih.Hash)
			ctx.pubAppAndImageToHash.Unpublish(aih.Key())
		}
	}
	log.Infof("purgeAppAndImageHash(%s) done", appUUID)
}

// Returns "" string if not found
func lookupAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID,
	imageID uuid.UUID, purgeCounter uint32) string {

	log.Infof("lookupAppAndImageHash(%s, %s, %d)", appUUID, imageID, purgeCounter)
	temp := types.AppAndImageToHash{
		AppUUID:      appUUID,
		ImageID:      imageID,
		PurgeCounter: purgeCounter,
	}
	item, _ := ctx.pubAppAndImageToHash.Get(temp.Key())
	if item == nil {
		log.Infof("lookupAppAndImageHash(%s, %s, %d) not found",
			appUUID, imageID, purgeCounter)
		return ""
	}
	aih := item.(types.AppAndImageToHash)
	log.Infof("lookupAppAndImageHash(%s, %s, %d) found %s",
		appUUID, imageID, purgeCounter, aih.Hash)
	return aih.Hash
}
