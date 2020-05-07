// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// AddOrRefcountDownloaderConfigCT used to publish the downloader config
func AddOrRefcountDownloaderConfigCT(ctx *volumemgrContext, status types.ContentTreeStatus) {

	log.Infof("AddOrRefcountDownloaderConfig for %s", status.ContentSha256)

	refCount := uint(1)
	m := lookupDownloaderConfig(ctx, status.ObjType, status.ContentSha256)
	if m != nil {
		log.Infof("downloader config exists for %s to refcount %d",
			status.ContentID, m.RefCount)
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
			status.ContentSha256)
	}
	name := status.RelativeURL

	// where should the final downloaded file be?
	locFilename := path.Join(types.DownloadDirname, status.ObjType, "pending", status.ContentID.String(), path.Base(name))
	// try to reserve storage, must be released on error
	size := status.MaxDownSize

	n := types.DownloaderConfig{
		ImageID:     status.ContentID,
		DatastoreID: status.DatastoreID,
		// XXX StorageConfig.Name is what?
		Name:        name, // XXX URL? DisplayName?
		NameIsURL:   status.NameIsURL,
		ImageSha256: status.ContentSha256,
		AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
			types.AppImgObj),
		Size:     size,
		Target:   locFilename,
		RefCount: refCount,
	}
	log.Infof("AddOrRefcountDownloaderConfig: DownloaderConfig: %+v", n)
	publishDownloaderConfig(ctx, status.ObjType, &n)
	log.Infof("AddOrRefcountDownloaderConfig done for %s",
		status.ContentSha256)
}
