// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// AddOrRefcountDownloaderConfig used to publish the downloader config
func AddOrRefcountDownloaderConfig(ctx *volumemgrContext, blob types.BlobStatus) {

	log.Functionf("AddOrRefcountDownloaderConfig for %s", blob.Sha256)

	refCount := uint(1)
	m := lookupDownloaderConfig(ctx, blob.Sha256)
	if m != nil {
		log.Functionf("downloader config exists for %s to refcount %d", blob.Sha256, m.RefCount)
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
		log.Tracef("AddOrRefcountDownloaderConfig: add for %s", blob.Sha256)
	}

	// where should the final downloaded file be?
	// Pick a unique name since the sha has not yet been verified hence
	// can potentially collide between different concurrent downloads
	id, err := uuid.NewV4()
	if err != nil {
		log.Errorf("NewV4 failed: %v", err)
		return
	}
	pendingFile := id.String() + "." + blob.Sha256
	locFilename := path.Join(types.SealedDirName, "downloader", "pending",
		pendingFile)

	// try to reserve storage, must be released on error
	size := blob.Size
	n := types.DownloaderConfig{
		DatastoreID: blob.DatastoreID,
		Name:        blob.RelativeURL,
		ImageSha256: blob.Sha256,
		Size:        size,
		Target:      locFilename,
		RefCount:    refCount,
	}
	log.Functionf("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v", n)
	publishDownloaderConfig(ctx, &n)
	log.Functionf("AddOrRefcountDownloaderConfig done for %s", blob.Sha256)
}

// MaybeRemoveDownloaderConfig decrements Refcount of the given DownloaderConfig.
// If the Refcount of a DownloaderConfig reaches zero, the following sequence of handshake is performed
// before deleting DownloaderConfig:
// 1. volumeMgr publishes DownloaderConfig with Refcount = 0.
// 2. Downloader replies with a expired DownloaderStatus (RefCount = 0).
// 3. volumeMgr deletes the respective DownloaderConfig after receiving expired DownloaderStatus.
// 4. Downloader receives the delete notification and deletes DownloaderStatus along with the downloaded file.
//
// Note:
// > If download was in progress after #1, then the download progress notification for the DownloaderStatus will be
// ignored silently.
// > If DownloaderConfig's Refcount was incremented before #3, then expired notification from the
// Downloader will be ignored silently.
func MaybeRemoveDownloaderConfig(ctx *volumemgrContext, imageSha string) {
	log.Functionf("MaybeRemoveDownloaderConfig(%s)", imageSha)

	m := lookupDownloaderConfig(ctx, imageSha)
	if m == nil {
		log.Functionf("MaybeRemoveDownloaderConfig: config missing for %s",
			imageSha)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveDownloaderConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, ImageSha: %s, ",
			m.Name, m.ImageSha256)
	}
	m.RefCount -= 1
	log.Functionf("MaybeRemoveDownloaderConfig remaining RefCount %d for %s",
		m.RefCount, imageSha)

	publishDownloaderConfig(ctx, m)
	log.Functionf("MaybeRemoveDownloaderConfig done for %s", imageSha)
}

func publishDownloaderConfig(ctx *volumemgrContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Tracef("publishDownloaderConfig(%s)", key)
	pub := ctx.pubDownloaderConfig
	pub.Publish(key, *config)
	log.Tracef("publishDownloaderConfig(%s) Done", key)
}

func unpublishDownloaderConfig(ctx *volumemgrContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Tracef("unpublishDownloaderConfig(%s)", key)
	pub := ctx.pubDownloaderConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishDownloaderConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishDownloaderConfig(%s) Done", key)
}

func handleDownloaderStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleDownloaderStatusImpl(ctxArg, key, statusArg)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleDownloaderStatusImpl(ctxArg, key, statusArg)
}

func handleDownloaderStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DownloaderStatus)
	ctx := ctxArg.(*volumemgrContext)
	log.Functionf("handleDownloaderStatusImpl for %s status.RefCount %d "+
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
		log.Functionf("handleDownloaderStatusImpl expired - deleting config %s",
			key)
		unpublishDownloaderConfig(ctx, config)

		return
	} else if status.Expired {
		log.Functionf("handleDownloaderStatusImpl ignore expired DownloaderStatus; "+
			"config still has reference for %s", key)
	}

	// Normal update case
	updateStatusByBlob(ctx, status.ImageSha256)
	log.Functionf("handleDownloaderStatusImpl done for %s", status.ImageSha256)
}

func lookupDownloaderConfig(ctx *volumemgrContext,
	key string) *types.DownloaderConfig {

	pub := ctx.pubDownloaderConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupDownloaderConfig(%s) not found", key)
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
		log.Tracef("lookupDownloaderStatus(%s) not found", key)
		return nil
	}
	status := c.(types.DownloaderStatus)
	return &status
}

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleDownloaderStatusDelete for %s", key)
	ctx := ctxArg.(*volumemgrContext)
	status := statusArg.(types.DownloaderStatus)
	updateStatusByBlob(ctx, status.ImageSha256)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupDownloaderConfig(ctx, status.ImageSha256)
	if config != nil && config.RefCount == 0 {
		log.Functionf("handleDownloaderStatusDelete delete config for %s",
			key)
		unpublishDownloaderConfig(ctx, config)
	}
	log.Functionf("handleDownloaderStatusDelete done for %s", key)
}
