// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"os"
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func AddOrRefcountDownloaderConfig(ctx *volumemgrContext, status types.VolumeStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s", status.BlobSha256)

	m := lookupDownloaderConfig(ctx, status.ObjType, status.BlobSha256)
	if m != nil {
		m.RefCount += 1
		log.Infof("downloader config exists for %s to refcount %d",
			status.VolumeID, m.RefCount)
		publishDownloaderConfig(ctx, status.ObjType, m)
	} else {
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s",
			status.BlobSha256)

		name := status.DownloadOrigin.Name

		// where should the final downloaded file be?
		locFilename := path.Join(types.DownloadDirname, status.ObjType, "pending", status.VolumeID.String(), path.Base(name))
		// try to reserve storage, must be released on error
		size := status.DownloadOrigin.MaxSizeBytes // XXX should this be MaxSize
		kb := types.RoundupToKB(size)
		if ret, errStr := tryReserveSpace(ctx, &status, kb, name); !ret {
			// *** THIS NEEDS TO BE FIXED
			// it is still the old one from downloader
			// instead, we need our own retry loop here on space
			status.RetryCount++
			publishVolumeStatus(ctx, &status)
			// *** END NEEDS TO BE FIXED
			log.Errorf("AddOrRefcountDownloaderConfig(%s): deferred with %s", name, errStr)
			return
		}

		n := types.DownloaderConfig{
			ImageID:     status.VolumeID,
			DatastoreID: status.DownloadOrigin.DatastoreID,
			// XXX StorageConfig.Name is what?
			Name:        name, // XXX URL? DisplayName?
			NameIsURL:   status.DownloadOrigin.NameIsURL,
			ImageSha256: status.DownloadOrigin.ImageSha256,
			IsContainer: status.DownloadOrigin.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			Size:     size,
			Target:   locFilename,
			RefCount: 1,
		}
		log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v", n)
		publishDownloaderConfig(ctx, status.ObjType, &n)
	}
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
			"0 RefCount. Image Details - Name: %s, ImageSha: %s, "+
			"IsContainer: %t",
			m.Name, m.ImageSha256, m.IsContainer)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveDownloaderConfig remaining RefCount %d for %s",
		m.RefCount, imageSha)
	publishDownloaderConfig(ctx, objType, m)
}

func publishDownloaderConfig(ctx *volumemgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)", key)
	pub := ctx.publication(*config, objType)
	pub.Publish(key, *config)
}

func unpublishDownloaderConfig(ctx *volumemgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s)", key)
	pub := ctx.publication(*config, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVerifyImageConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func unpublishClearSpace(ctx *volumemgrContext, status *types.VolumeStatus, name string) {
	deleteSpace(ctx, status, name)

	// clear up used space
	unreserveSpace(ctx, status, name)
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
			// IsContainer might not be known by downloader
			IsContainer: status.IsContainer,
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
		if volStatus := lookupVolumeStatus(ctx, status.ObjType, config.Key()); volStatus != nil {
			unpublishClearSpace(ctx, volStatus, config.Name)
		}

		return
	}
	if status.HasError() {
		// free the reserved storage
		if volStatus := lookupVolumeStatus(ctx, status.ObjType, config.Key()); volStatus != nil {
			unpublishClearSpace(ctx, volStatus, config.Name)
		}
	}
	// completion of download
	if !status.HasError() && status.State == types.DOWNLOADED {
		locFilename := config.Target
		info, err := os.Stat(locFilename)
		if err != nil {
			log.Errorf("handleDownloaderStatusModify(%s): failed to read returned file %s",
				config.Name, err)
			return
		}
		size := uint64(info.Size())
		// we need to release the reserved space
		// and convert it to used space
		if volStatus := lookupVolumeStatus(ctx, status.ObjType, config.Key()); volStatus != nil {
			allocateSpace(ctx, volStatus, size, config.Name)
		}
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
		if volStatus := lookupVolumeStatus(ctx, status.ObjType, config.Key()); volStatus != nil {
			unpublishClearSpace(ctx, volStatus, config.Name)
		}
	}
	log.Infof("handleDownloaderStatusDelete done for %s", key)
}
