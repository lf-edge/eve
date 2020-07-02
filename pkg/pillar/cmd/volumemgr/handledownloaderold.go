// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// AddOrRefcountDownloaderConfigOld used to publish the downloader config
func AddOrRefcountDownloaderConfigOld(ctx *volumemgrContext, status types.OldVolumeStatus) {

	log.Infof("AddOrRefcountDownloaderConfigOld for %s", status.BlobSha256)

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
		log.Debugf("AddOrRefcountDownloaderConfigOld: add for %s",
			status.BlobSha256)
	}
	name := status.DownloadOrigin.Name

	// where should the final downloaded file be?
	locFilename := path.Join(types.DownloadDirname, status.ObjType, "pending", status.VolumeID.String(), path.Base(name))
	// try to reserve storage, must be released on error
	size := status.DownloadOrigin.MaxDownSize

	n := types.DownloaderConfig{
		DatastoreID: status.DownloadOrigin.DatastoreID,
		Name:        name,
		NameIsURL:   status.DownloadOrigin.NameIsURL,
		ImageSha256: status.DownloadOrigin.ImageSha256,
		AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
			types.AppImgObj),
		Size:     size,
		Target:   locFilename,
		RefCount: refCount,
	}
	log.Infof("AddOrRefcountDownloaderConfigOld: DownloaderConfig: %+v", n)
	publishDownloaderConfig(ctx, status.ObjType, &n)
	log.Infof("AddOrRefcountDownloaderConfigOld done for %s",
		status.BlobSha256)
}
