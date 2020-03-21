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
func addAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID, imageID uuid.UUID, hash string) {
	log.Infof("addAppAndImageHash(%s, %s, %s)", appUUID, imageID, hash)
	if hash == "" {
		log.Errorf("addAppAndImageHash(%s, %s) empty hash",
			appUUID, imageID)
		return
	}
	aih := types.AppAndImageToHash{
		AppUUID: appUUID,
		ImageID: imageID,
		Hash:    hash,
	}
	item, _ := ctx.pubAppAndImageToHash.Get(aih.Key())
	if item != nil {
		old := item.(types.AppAndImageToHash)
		if old.Hash == aih.Hash {
			log.Warnf("addAppAndImageHash(%s, %s) no change %s",
				appUUID, imageID, old.Hash)
			return
		}
		log.Warnf("addAppAndImageHash(%s, %s) change from %s to %s",
			appUUID, imageID, old.Hash, aih.Hash)
	}
	ctx.pubAppAndImageToHash.Publish(aih.Key(), aih)
	log.Infof("addAppAndImageHash(%s, %s, %s) done", appUUID, imageID, hash)
}

// Delete for a specific image
func deleteAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID, imageID uuid.UUID) {
	log.Infof("deleteAppAndImageHash(%s, %s)", appUUID, imageID)
	aih := types.AppAndImageToHash{
		AppUUID: appUUID,
		ImageID: imageID,
	}
	item, _ := ctx.pubAppAndImageToHash.Get(aih.Key())
	if item == nil {
		log.Errorf("deleteAppAndImageHash(%s, %s) not found",
			appUUID, imageID)
		return
	}
	ctx.pubAppAndImageToHash.Unpublish(aih.Key())
	log.Infof("deleteAppAndImageHash(%s, %s) done", appUUID, imageID)
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
func lookupAppAndImageHash(ctx *zedmanagerContext, appUUID uuid.UUID, imageID uuid.UUID) string {
	log.Infof("lookupAppAndImageHash(%s, %s)", appUUID, imageID)
	temp := types.AppAndImageToHash{
		AppUUID: appUUID,
		ImageID: imageID,
	}
	item, _ := ctx.pubAppAndImageToHash.Get(temp.Key())
	if item == nil {
		log.Infof("lookupAppAndImageHash(%s, %s) not found",
			appUUID, imageID)
		return ""
	}
	aih := item.(types.AppAndImageToHash)
	log.Infof("lookupAppAndImageHash(%s, %s) found %s",
		appUUID, imageID, aih.Hash)
	return aih.Hash
}
