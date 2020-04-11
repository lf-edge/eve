// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

func AddOrRefcountDownloaderConfig(ctx *volumemgrContext, status types.VolumeStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s\n", status.VolumeID)

	m := lookupDownloaderConfig(ctx, status.ObjType, status.VolumeID)
	if m != nil {
		m.RefCount += 1
		if m.IsContainer != status.DownloadOrigin.IsContainer {
			log.Infof("change IsContainer to %t for %s",
				status.DownloadOrigin.IsContainer, status.VolumeID)
		}
		log.Infof("downloader config exists for %s to refcount %d\n",
			status.VolumeID, m.RefCount)
		publishDownloaderConfig(ctx, status.ObjType, m)
	} else {
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s\n",
			status.VolumeID)
		n := types.DownloaderConfig{
			ImageID:     status.VolumeID,
			DatastoreID: status.DownloadOrigin.DatastoreID,
			// XXX StorageConfig.Name is what?
			Name:        status.DownloadOrigin.Name, // XXX URL? DisplayName?
			NameIsURL:   status.DownloadOrigin.NameIsURL,
			IsContainer: status.DownloadOrigin.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:     status.DownloadOrigin.MaxSizeBytes, // XXX should this be MaxSize
			RefCount: 1,
		}
		log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v\n", n)
		publishDownloaderConfig(ctx, status.ObjType, &n)
	}
	log.Infof("AddOrRefcountDownloaderConfig done for %s\n",
		status.VolumeID)
}

func MaybeRemoveDownloaderConfig(ctx *volumemgrContext, objType string, imageID uuid.UUID) {
	log.Infof("MaybeRemoveDownloaderConfig(%s) for %s\n", imageID, objType)

	m := lookupDownloaderConfig(ctx, objType, imageID)
	if m == nil {
		log.Infof("MaybeRemoveDownloaderConfig: config missing for %s\n",
			imageID)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveDownloaderConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, ImageID: %s, "+
			"IsContainer: %t\n",
			m.Name, m.ImageID, m.IsContainer)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveDownloaderConfig remaining RefCount %d for %s\n",
		m.RefCount, imageID)
	publishDownloaderConfig(ctx, objType, m)
}

func publishDownloaderConfig(ctx *volumemgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)\n", key)
	pub := ctx.publication(*config, objType)
	pub.Publish(key, *config)
}

func unpublishDownloaderConfig(ctx *volumemgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s)\n", key)
	pub := ctx.publication(*config, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVerifyImageConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.DownloaderStatus)
	ctx := ctxArg.(*volumemgrContext)
	log.Infof("handleDownloaderStatusModify for %s status.RefCount %d"+
		"status.Expired: %+v\n",
		status.ImageID, status.RefCount, status.Expired)

	// Handling even if Pending is set to process Progress updates

	// XXX still need this downloader handshake?
	// We handle two special cases in the handshake here
	// 1. downloader added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. downloader set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupDownloaderConfig(ctx, status.ObjType, status.ImageID)
	if config == nil && status.RefCount == 0 {
		log.Infof("handleDownloaderStatusModify adding RefCount=0 config %s\n",
			key)
		n := types.DownloaderConfig{
			ImageID:     status.ImageID,
			DatastoreID: status.DatastoreID,
			Name:        status.Name,
			NameIsURL:   status.NameIsURL,
			// IsContainer might not be known by downloader
			IsContainer: status.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:     status.Size,
			RefCount: 0,
		}
		publishDownloaderConfig(ctx, status.ObjType, &n)
		return
	}
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("handleDownloaderStatusModify expired - deleting config %s\n",
			key)
		unpublishDownloaderConfig(ctx, status.ObjType, config)
		return
	}

	// Normal update case
	updateVolumeStatus(ctx, status.ObjType, status.ImageID)
	log.Infof("handleDownloaderStatusModify done for %s\n", status.ImageID)
}

func lookupDownloaderConfig(ctx *volumemgrContext, objType string,
	imageID uuid.UUID) *types.DownloaderConfig {

	pub := ctx.publication(types.DownloaderConfig{}, objType)
	c, _ := pub.Get(imageID.String())
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s) not found\n", imageID)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *volumemgrContext, objType string,
	imageID uuid.UUID) *types.DownloaderStatus {

	sub := ctx.subscription(types.DownloaderStatus{}, objType)
	c, _ := sub.Get(imageID.String())
	if c == nil {
		log.Infof("lookupDownloaderStatus(%s) not found\n", imageID)
		return nil
	}
	status := c.(types.DownloaderStatus)
	return &status
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDownloaderStatusDelete for %s\n", key)
	ctx := ctxArg.(*volumemgrContext)
	status := statusArg.(types.DownloaderStatus)
	updateVolumeStatus(ctx, status.ObjType, status.ImageID)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupDownloaderConfig(ctx, status.ObjType, status.ImageID)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleDownloaderStatusDelete delete config for %s\n",
			key)
		unpublishDownloaderConfig(ctx, status.ObjType, config)
	}
	log.Infof("handleDownloaderStatusDelete done for %s\n", key)
}
