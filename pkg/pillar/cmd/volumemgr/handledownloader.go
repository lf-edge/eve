// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// AddOrRefcountDownloaderConfig used to publish the downloader config
// The objType is only used to determine the free/not-free download setting
func AddOrRefcountDownloaderConfig(ctx *volumemgrContext, objType string, blob types.BlobStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s", blob.Sha256)

	refCount := uint(1)
	m := lookupDownloaderConfig(ctx, blob.Sha256)
	if m != nil {
		log.Infof("downloader config exists for %s to refcount %d", blob.Sha256, m.RefCount)
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
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s", blob.Sha256)
	}

	// where should the final downloaded file be?
	// Pick a unique name since the sha has not yet been verified hence
	// can potentially collide between different concurrent downloads
	pendingFile := uuid.NewV4().String() + "." + blob.Sha256
	locFilename := path.Join(types.SealedDirName, "downloader", "pending",
		pendingFile)

	// try to reserve storage, must be released on error
	size := blob.Size

	n := types.DownloaderConfig{
		DatastoreID:      blob.DatastoreID,
		Name:             blob.RelativeURL,
		ImageSha256:      blob.Sha256,
		AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig, objType),
		Size:             size,
		Target:           locFilename,
		RefCount:         refCount,
	}
	log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v", n)
	publishDownloaderConfig(ctx, &n)
	log.Infof("AddOrRefcountDownloaderConfig done for %s", blob.Sha256)
}

func MaybeRemoveDownloaderConfig(ctx *volumemgrContext, imageSha string) {
	log.Infof("MaybeRemoveDownloaderConfig(%s)", imageSha)

	m := lookupDownloaderConfig(ctx, imageSha)
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
		unpublishDownloaderConfig(ctx, m)
	} else {
		publishDownloaderConfig(ctx, m)
	}
	log.Infof("MaybeRemoveDownloaderConfig done for %s", imageSha)
}

func publishDownloaderConfig(ctx *volumemgrContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)", key)
	pub := ctx.pubDownloaderConfig
	pub.Publish(key, *config)
	log.Debugf("publishDownloaderConfig(%s) Done", key)
}

func unpublishDownloaderConfig(ctx *volumemgrContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s)", key)
	pub := ctx.pubDownloaderConfig
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
	log.Infof("handleDownloaderStatusModify for %s status.RefCount %d "+
		"status.Expired: %+v ENTIRE: %+v",
		status.ImageSha256, status.RefCount, status.Expired, status)

	// Handling even if Pending is set to process Progress updates

	// We handle one special case in the handshake here, which is when
	// downloader sets Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.
	// If we have a config with non-zero RefCount it means there was
	// a race and downloader will see the RefCount increase and clear the
	// Expired flag (and not delete the file).

	config := lookupDownloaderConfig(ctx, status.ImageSha256)
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("handleDownloaderStatusModify expired - deleting config %s",
			key)
		unpublishDownloaderConfig(ctx, config)

		return
	}

	// Normal update case
	updateStatus(ctx, status.ImageSha256)
	log.Infof("handleDownloaderStatusModify done for %s", status.ImageSha256)
}

func lookupDownloaderConfig(ctx *volumemgrContext,
	key string) *types.DownloaderConfig {

	pub := ctx.pubDownloaderConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Debugf("lookupDownloaderConfig(%s) not found", key)
		return nil
	}
	config := c.(types.DownloaderConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *volumemgrContext,
	key string) *types.DownloaderStatus {

	sub := ctx.subDownloaderStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Debugf("lookupDownloaderStatus(%s) not found", key)
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
	updateStatus(ctx, status.ImageSha256)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupDownloaderConfig(ctx, status.ImageSha256)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleDownloaderStatusDelete delete config for %s",
			key)
		unpublishDownloaderConfig(ctx, config)
	}
	log.Infof("handleDownloaderStatusDelete done for %s", key)
}
