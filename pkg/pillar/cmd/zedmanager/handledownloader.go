// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func AddOrRefcountDownloaderConfig(ctx *zedmanagerContext, safename string,
	ss types.StorageStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s\n", safename)
	log.Infof("AddOrRefcountDownloaderConfig: StorageStatus: %+v\n", ss)

	m := lookupDownloaderConfig(ctx, safename)
	if m != nil {
		m.RefCount += 1
		log.Infof("downloader config exists for %s to refcount %d\n",
			safename, m.RefCount)
		publishDownloaderConfig(ctx, m)
	} else {
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s\n",
			safename)
		n := types.DownloaderConfig{
			DatastoreID: ss.DatastoreID,
			ImageID:     ss.ImageID,
			Safename:    safename,
			Name:        ss.Name,
			NameIsURL:   ss.NameIsURL,
			IsContainer: ss.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:        ss.Size,
			ImageSha256: ss.ImageSha256,
			RefCount:    1,
		}
		log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v\n", n)
		publishDownloaderConfig(ctx, &n)
	}
	log.Infof("AddOrRefcountDownloaderConfig done for %s\n",
		safename)
}

func MaybeRemoveDownloaderConfig(ctx *zedmanagerContext, safename string) {
	log.Infof("MaybeRemoveDownloaderConfig for %s\n", safename)

	m := lookupDownloaderConfig(ctx, safename)
	if m == nil {
		log.Infof("MaybeRemoveDownloaderConfig: config missing for %s\n",
			safename)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveDownloaderConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, SafeName: %s, "+
			"ImageSha256:%s, IsContainer: %t\n",
			m.Name, m.Safename, m.ImageSha256, m.IsContainer)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveDownloaderConfig remaining RefCount %d for %s\n",
		m.RefCount, safename)
	publishDownloaderConfig(ctx, m)
}

func publishDownloaderConfig(ctx *zedmanagerContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)\n", key)
	pub := ctx.pubAppImgDownloadConfig
	pub.Publish(key, config)
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
	status := cast.CastDownloaderStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleDownloaderStatusModify for %s status.RefCount %d"+
		"status.Expired: %+v\n",
		status.Safename, status.RefCount, status.Expired)

	// Handling even if Pending is set to process Progress updates

	// We handle two special cases in the handshake here
	// 1. downloader added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. downloader set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupDownloaderConfig(ctx, status.Key())
	if config == nil && status.RefCount == 0 {
		log.Infof("handleDownloaderStatusModify adding RefCount=0 config %s\n",
			key)
		n := types.DownloaderConfig{
			DatastoreID: status.DatastoreID,
			Safename:    status.Safename,
			Name:        status.Name,
			NameIsURL:   status.NameIsURL,
			IsContainer: status.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:        status.Size,
			ImageSha256: status.ImageSha256,
			RefCount:    0,
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

	updateContainerImageID := false
	if status.IsContainer {
		updateContainerImageID = true
	}

	// Normal update case
	updateAIStatusWithStorageSafename(ctx, key, updateContainerImageID, status.ContainerImageID)
	log.Infof("handleDownloaderStatusModify done for %s\n",
		status.Safename)
}

func lookupDownloaderConfig(ctx *zedmanagerContext,
	safename string) *types.DownloaderConfig {

	pub := ctx.pubAppImgDownloadConfig
	c, _ := pub.Get(safename)
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s) not found\n", safename)
		return nil
	}
	config := cast.CastDownloaderConfig(c)
	if config.Key() != safename {
		log.Errorf("lookupDownloaderConfig(%s) got %s; ignored %+v\n",
			safename, config.Key(), config)
		return nil
	}
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *zedmanagerContext,
	safename string) *types.DownloaderStatus {

	sub := ctx.subAppImgDownloadStatus
	c, _ := sub.Get(safename)
	if c == nil {
		log.Infof("lookupDownloaderStatus(%s) not found\n", safename)
		return nil
	}
	status := cast.CastDownloaderStatus(c)
	if status.Key() != safename {
		log.Errorf("lookupDownloaderStatus(%s) got %s; ignored %+v\n",
			safename, status.Key(), status)
		return nil
	}
	return &status
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDownloaderStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusSafename(ctx, key)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupDownloaderConfig(ctx, key)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleDownloaderStatusDelete delete config for %s\n",
			key)
		unpublishDownloaderConfig(ctx, config)
	}
	log.Infof("handleDownloaderStatusDelete done for %s\n", key)
}
