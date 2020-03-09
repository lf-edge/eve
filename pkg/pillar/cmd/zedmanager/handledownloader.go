// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

func AddOrRefcountDownloaderConfig(ctx *zedmanagerContext, imageID uuid.UUID,
	ss types.StorageStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s\n", imageID)
	log.Infof("AddOrRefcountDownloaderConfig: StorageStatus: %+v\n", ss)

	m := lookupDownloaderConfig(ctx, imageID, ss.ImageSha256)
	if m != nil {
		m.RefCount += 1
		if m.IsContainer != ss.IsContainer {
			log.Infof("change IsContainer to %t for %s",
				ss.IsContainer, imageID)
		}
		log.Infof("downloader config exists for %s to refcount %d\n",
			imageID, m.RefCount)
		publishDownloaderConfig(ctx, m)
	} else {
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s\n",
			imageID)
		n := types.DownloaderConfig{
			ImageID:     ss.ImageID,
			DatastoreID: ss.DatastoreID,
			Name:        ss.Name,
			NameIsURL:   ss.NameIsURL,
			IsContainer: ss.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:        ss.Size,
			RefCount:    1,
			ImageSha256: ss.ImageSha256,
		}
		log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v\n", n)
		publishDownloaderConfig(ctx, &n)
	}
	log.Infof("AddOrRefcountDownloaderConfig done for %s\n",
		imageID)
}

func MaybeRemoveDownloaderConfig(ctx *zedmanagerContext, imageID uuid.UUID, imageSha256 string) {
	log.Infof("MaybeRemoveDownloaderConfig for %s\n", imageID)

	m := lookupDownloaderConfig(ctx, imageID, imageSha256)
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
	publishDownloaderConfig(ctx, m)
}

func publishDownloaderConfig(ctx *zedmanagerContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)\n", key)
	pub := ctx.pubAppImgDownloadConfig
	pub.Publish(key, *config)
}

func unpublishDownloaderConfig(ctx *zedmanagerContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s)\n", key)
	pub := ctx.pubAppImgDownloadConfig
	pub.Unpublish(key)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.DownloaderStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleDownloaderStatusModify for %s status.RefCount %d"+
		"status.Expired: %+v\n",
		status.ImageID, status.RefCount, status.Expired)

	// Handling even if Pending is set to process Progress updates

	// We handle two special cases in the handshake here
	// 1. downloader added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. downloader set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupDownloaderConfig(ctx, status.ImageID, status.ImageSha256)
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
			Size:        status.Size,
			RefCount:    0,
			ImageSha256: status.ImageSha256,
		}
		publishDownloaderConfig(ctx, &n)
		return
	}
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("handleDownloaderStatusModify expired - deleting config %s\n",
			key)
		unpublishDownloaderConfig(ctx, config)
		return
	}

	// Normal update case
	updateAIStatusWithStorageImageID(ctx, status.ImageID)
	log.Infof("handleDownloaderStatusModify done for %s\n", status.ImageID)
}

func lookupDownloaderConfig(ctx *zedmanagerContext,
	imageID uuid.UUID, imageSha256 string) *types.DownloaderConfig {

	pub := ctx.pubAppImgDownloadConfig
	c, _ := pub.Get(fmt.Sprintf("%s.%s", imageID.String(), imageSha256))
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s.%s) not found\n", imageID, imageSha256)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *zedmanagerContext,
	imageID uuid.UUID, imageSha256 string) *types.DownloaderStatus {

	sub := ctx.subAppImgDownloadStatus
	c, _ := sub.Get(fmt.Sprintf("%s.%s", imageID.String(), imageSha256))
	if c == nil {
		log.Infof("lookupDownloaderStatus(%s.%s) not found\n", imageID, imageSha256)
		return nil
	}
	status := c.(types.DownloaderStatus)
	return &status
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDownloaderStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.DownloaderStatus)
	removeAIStatusImageID(ctx, status.ImageID)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupDownloaderConfig(ctx, status.ImageID, status.ImageSha256)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleDownloaderStatusDelete delete config for %s\n",
			key)
		unpublishDownloaderConfig(ctx, config)
	}
	log.Infof("handleDownloaderStatusDelete done for %s\n", key)
}
