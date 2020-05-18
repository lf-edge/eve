// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func AddOrRefcountDownloaderConfig(ctx *volumemgrContext, status types.VolumeStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s", status.BlobSha256)

	refCount := uint(1)
	m := lookupDownloaderConfig(ctx, status.ObjType, status.BlobSha256)
	if m != nil {
		log.Infof("downloader config exists for %s to refcount %d",
			status.VolumeID, m.RefCount)
		refCount = m.RefCount + 1
		// We need to update datastore id before publishing the
		// datastore config because datastore id can be updated
		// in some cases. For example:
		// 1. Deploy an instance, image will start downloading (~40G)
		// 2. Delete the instance before the download completion
		// 3. Delete the datastore and image which results to failure
		//    of the already running download process.
		// 4. Recreate datastore and image with same name, EVC will
		//    create new UUID for objects this time.
		// 5. Deploy an instance, it will fail because SHA is same of
		//    the image and downloader will look up for old datastore
		//    id which was deleted.
		// So, we need to update the datastore id everytime.
		// For VM images, we allow changing of size in image config
		// after creating an object. So, we need to update the size
		// in the downloader config before publishing
		// Same is true for other fields
	} else {
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s",
			status.BlobSha256)
	}
	name := status.DownloadOrigin.Name

	// where should the final downloaded file be?
	locFilename := path.Join(types.DownloadDirname, status.ObjType, "pending", status.VolumeID.String(), path.Base(name))
	// try to reserve storage, must be released on error
	size := status.DownloadOrigin.MaxSizeBytes // XXX should this be MaxSize

	n := types.DownloaderConfig{
		ImageID:     status.VolumeID,
		DatastoreID: status.DownloadOrigin.DatastoreID,
		// XXX StorageConfig.Name is what?
		Name:        name, // XXX URL? DisplayName?
		NameIsURL:   status.DownloadOrigin.NameIsURL,
		ImageSha256: status.DownloadOrigin.ImageSha256,
		AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
			types.AppImgObj),
		Size:     size,
		Target:   locFilename,
		RefCount: refCount,
	}
	log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v", n)
	publishDownloaderConfig(ctx, status.ObjType, &n)
	log.Infof("AddOrRefcountDownloaderConfig done for %s",
		status.BlobSha256)
}

func MaybeRemoveDownloaderConfig(ctx *volumemgrContext, objType string, imageSha string) {
	log.Infof("MaybeRemoveDownloaderConfig(%s) for %s", imageSha, objType)

	m := lookupDownloaderConfig(ctx, objType, imageSha)
	if m == nil {
		log.Infof("MaybeRemoveDownloaderConfig: config missing for %s",
			imageSha)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveDownloaderConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, ImageSha: %s, ",
			m.Name, m.ImageSha256)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveDownloaderConfig remaining RefCount %d for %s",
		m.RefCount, imageSha)
	if m.RefCount == 0 {
		unpublishDownloaderConfig(ctx, objType, m)
	} else {
		publishDownloaderConfig(ctx, objType, m)
	}
	log.Infof("MaybeRemoveDownloaderConfig done for %s", imageSha)
}

func publishDownloaderConfig(ctx *volumemgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)", key)
	pub := ctx.publication(*config, objType)
	pub.Publish(key, *config)
	log.Debugf("publishDownloaderConfig(%s) Done", key)
}

func unpublishDownloaderConfig(ctx *volumemgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s)", key)
	pub := ctx.publication(*config, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishDownloaderConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishDownloaderConfig(%s) Done", key)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.DownloaderStatus)
	ctx := ctxArg.(*volumemgrContext)
	log.Infof("handleDownloaderStatusModify for %s status.RefCount %d"+
		"status.Expired: %+v",
		status.ImageSha256, status.RefCount, status.Expired)

	// Handling even if Pending is set to process Progress updates

	// XXX still need this downloader handshake?
	// We handle two special cases in the handshake here
	// 1. downloader added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. downloader set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupDownloaderConfig(ctx, status.ObjType, status.ImageSha256)
	if config == nil && status.RefCount == 0 {
		log.Infof("handleDownloaderStatusModify adding RefCount=0 config %s",
			key)

		// where should the final downloaded file be?
		locFilename := path.Join(types.DownloadDirname, status.ObjType, "pending", status.ImageID.String(), path.Base(status.Name))

		n := types.DownloaderConfig{
			ImageID:     status.ImageID,
			DatastoreID: status.DatastoreID,
			Name:        status.Name,
			NameIsURL:   status.NameIsURL,
			ImageSha256: status.ImageSha256,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:     status.Size,
			RefCount: 0,
			Target:   locFilename,
		}
		publishDownloaderConfig(ctx, status.ObjType, &n)
		return
	}
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("handleDownloaderStatusModify expired - deleting config %s",
			key)
		unpublishDownloaderConfig(ctx, status.ObjType, config)

		return
	}

	// Normal update case
	updateVolumeStatus(ctx, status.ObjType, status.ImageSha256, status.ImageID)
	log.Infof("handleDownloaderStatusModify done for %s", status.ImageSha256)
}

func lookupDownloaderConfig(ctx *volumemgrContext, objType,
	key string) *types.DownloaderConfig {

	pub := ctx.publication(types.DownloaderConfig{}, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *volumemgrContext, objType,
	key string) *types.DownloaderStatus {

	sub := ctx.subscription(types.DownloaderStatus{}, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupDownloaderStatus(%s) not found", key)
		return nil
	}
	status := c.(types.DownloaderStatus)
	return &status
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDownloaderStatusDelete for %s", key)
	ctx := ctxArg.(*volumemgrContext)
	status := statusArg.(types.DownloaderStatus)
	updateVolumeStatus(ctx, status.ObjType, status.ImageSha256, status.ImageID)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupDownloaderConfig(ctx, status.ObjType, status.ImageSha256)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleDownloaderStatusDelete delete config for %s",
			key)
		unpublishDownloaderConfig(ctx, status.ObjType, config)
	}
	log.Infof("handleDownloaderStatusDelete done for %s", key)
}
