// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"

	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
)

func handleContentTreeCreateAppImg(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleContentTreeCreateAppImg(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := createContentTreeStatus(ctx, config, types.AppImgObj)
	updateContentTree(ctx, status)
	log.Functionf("handleContentTreeCreateAppImg(%s) Done", key)
}

func handleContentTreeModifyAppImg(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("handleContentTreeModifyAppImg(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.AppImgObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	updateContentTree(ctx, status)
	log.Functionf("handleContentTreeAppImg(%s) Done", key)
}

func handleContentTreeDeleteAppImg(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleContentTreeDeleteAppImg(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.AppImgObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	deleteContentTree(ctx, status)
	log.Functionf("handleContentTreeDeleteAppImg(%s) Done", key)
}

func handleContentTreeCreateBaseOs(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleContentTreeCreateBaseOs(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := createContentTreeStatus(ctx, config, types.BaseOsObj)
	updateContentTree(ctx, status)
	log.Functionf("handleContentTreeCreateBaseOs(%s) Done", key)
}

func handleContentTreeModifyBaseOs(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("handleContentTreeModifyBaseOs(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.BaseOsObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	updateContentTree(ctx, status)
	log.Functionf("handleContentTreeModifyBaseOs(%s) Done", key)
}

func handleContentTreeDeleteBaseOs(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleContentTreeDeleteBaseOs(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.BaseOsObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	deleteContentTree(ctx, status)
	log.Functionf("handleContentTreeDeleteBaseOs(%s) Done", key)
}

func handleContentTreeRestart(ctxArg interface{}, done bool) {
	log.Functionf("handleContentTreeRestart(%v)", done)
	ctx := ctxArg.(*volumemgrContext)
	ctx.contentTreeRestarted = true
}

func publishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Tracef("publishContentTreeStatus(%s)", key)
	pub := ctx.publication(types.ContentTreeStatus{}, status.ObjType)
	pub.Publish(key, *status)
	log.Tracef("publishContentTreeStatus(%s) Done", key)
}

func unpublishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Tracef("unpublishContentTreeStatus(%s)", key)
	pub := ctx.publication(types.ContentTreeStatus{}, status.ObjType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishContentTreeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishContentTreeStatus(%s) Done", key)
}

func lookupContentTreeStatus(ctx *volumemgrContext,
	key, objType string) *types.ContentTreeStatus {

	log.Tracef("lookupContentTreeStatus(%s/%s)", key, objType)
	pub := ctx.publication(types.ContentTreeStatus{}, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupContentTreeStatus(%s/%s) not found", key, objType)
		return nil
	}
	status := c.(types.ContentTreeStatus)
	log.Tracef("lookupContentTreeStatus(%s/%s) Done", key, objType)
	return &status
}

// lookupContentTreeStatusAny assumes there is one CT with the key and looks
// for all objTypes
func lookupContentTreeStatusAny(ctx *volumemgrContext, key string) *types.ContentTreeStatus {

	for _, objType := range ctObjTypes {
		status := lookupContentTreeStatus(ctx, key, objType)
		if status != nil {
			return status
		}
	}
	return nil
}

func getAllAppContentTreeStatus(ctx *volumemgrContext) map[string]*types.ContentTreeStatus {
	log.Tracef("getAllAppContentTreeStatus")
	pub := ctx.publication(types.ContentTreeStatus{}, types.AppImgObj)
	contentIDAndContentTreeStatusIntf := pub.GetAll()
	contentIDAndContentTreeStatus := make(map[string]*types.ContentTreeStatus)
	for contentIDKey, contentTreeStatusIntf := range contentIDAndContentTreeStatusIntf {
		contentTreeStatus := contentTreeStatusIntf.(types.ContentTreeStatus)
		contentIDAndContentTreeStatus[contentIDKey] = &contentTreeStatus
	}
	log.Tracef("getAllAppContentTreeStatus")
	return contentIDAndContentTreeStatus
}

func lookupContentTreeConfig(ctx *volumemgrContext,
	key, objType string) *types.ContentTreeConfig {

	log.Tracef("lookupContentTreeConfig(%s/%s)", key, objType)
	sub := ctx.subscription(types.ContentTreeConfig{}, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupContentTreeConfig(%s/%s) not found", key, objType)
		return nil
	}
	config := c.(types.ContentTreeConfig)
	log.Tracef("lookupContentTreeConfig(%s/%s) Done", key, objType)
	return &config
}

func createContentTreeStatus(ctx *volumemgrContext, config types.ContentTreeConfig,
	objType string) *types.ContentTreeStatus {

	log.Functionf("createContentTreeStatus for %v objType %s", config.ContentID, objType)
	status := lookupContentTreeStatus(ctx, config.Key(), objType)
	if status == nil {
		// need to save the datastore type
		var datastoreType string
		datastoreConfig, err := utils.LookupDatastoreConfig(ctx.subDatastoreConfig, config.DatastoreID)
		if datastoreConfig == nil {
			log.Errorf("createContentTreeStatus(%s): datastoreConfig for %s not found %v", config.Key(), config.DatastoreID, err)
		} else {
			log.Tracef("Found datastore(%s) for %s", config.DatastoreID.String(), config.Key())
			datastoreType = datastoreConfig.DsType
		}

		status = &types.ContentTreeStatus{
			ContentID:         config.ContentID,
			DatastoreID:       config.DatastoreID,
			DatastoreType:     datastoreType,
			RelativeURL:       config.RelativeURL,
			Format:            config.Format,
			ContentSha256:     config.ContentSha256,
			MaxDownloadSize:   config.MaxDownloadSize,
			GenerationCounter: config.GenerationCounter,
			DisplayName:       config.DisplayName,
			ObjType:           objType,
			State:             types.INITIAL,
			Blobs:             []string{},
		}

		// we only publish the BlobStatus if we have the hash for it; this
		// might come later
		if config.ContentSha256 != "" {
			if lookupOrCreateBlobStatus(ctx, config.ContentSha256) == nil {
				// the blobType is binary unless we are dealing with OCI
				// in reality, this is not determined by the *format* but by the source,
				// i.e. an OCI registry may have other formats, no matter what the
				// image format is. This will do for now, though.
				mediaType := string(v1types.OCILayer)
				if config.Format == zconfig.Format_CONTAINER {
					// when first creating the root, the type is unknown,
					// but will be updated from the mediatype passed by the
					// Content-Type http header
					mediaType = ""
				}
				rootBlob := &types.BlobStatus{
					DatastoreID: config.DatastoreID,
					RelativeURL: config.RelativeURL,
					Sha256:      strings.ToLower(config.ContentSha256),
					Size:        config.MaxDownloadSize,
					State:       types.INITIAL,
					MediaType:   mediaType,
				}
				publishBlobStatus(ctx, rootBlob)
			}
			AddBlobsToContentTreeStatus(ctx, status, strings.ToLower(config.ContentSha256))
		}
	}
	publishContentTreeStatus(ctx, status)
	log.Functionf("createContentTreeStatus for %v Done", config.ContentID)
	return status
}

//AddBlobsToContentTreeStatus adds blob to ContentTreeStatus.Blobs also increments RefCount of the respective BlobStatus.
//NOTE: This should be the only method to add blobs into ContentTreeStatus.Blobs
func AddBlobsToContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus, blobShas ...string) error {
	log.Functionf("AddBlobsToContentTreeStatus(%s): for blobs %v", status.ContentID, blobShas)
	for _, blobSha := range blobShas {
		blobStatus := lookupBlobStatus(ctx, blobSha)
		if blobStatus == nil {
			err := fmt.Errorf("AddBlobsToContentTreeStatus(%s): No BlobStatus found for blobHash: %s",
				status.ContentID.String(), blobSha)
			log.Errorf(err.Error())
			return err
		}
		// Adding a blob to ContentTreeStatus and incrementing the refcount of that blob should be atomic as
		// we would depend on that while we remove a blob from ContentTreeStatus and decrement
		// the RefCount of that blob. In case if the blobs in a ContentTreeStatus in not in sync with the
		// corresponding Blob's Refcount, then that would lead to Fatal error.
		// If the same sha appears in multiple places in the ContentTree we intentionally add it twice to the list of
		// Blobs so that we can have two reference counts on that blob.
		status.Blobs = append(status.Blobs, blobSha)
		AddRefToBlobStatus(ctx, blobStatus)
	}
	return nil
}

//RemoveAllBlobsFromContentTreeStatus removes all the blob from ContentTreeStatus.Blobs also decrements RefCount of the
// respective BlobStatus.
//NOTE: This should be the only method to remove blobs from ContentTreeStatus.Blobs
func RemoveAllBlobsFromContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus, blobShas ...string) {
	log.Functionf("RemoveAllBlobsFromContentTreeStatus(%s): for blobs %v", status.ContentID, blobShas)
	for _, blobSha := range status.Blobs {
		blobStatus := lookupBlobStatus(ctx, blobSha)
		if blobStatus == nil {
			err := fmt.Errorf("RemoveAllBlobsFromContentTreeStatus(%s): No BlobStatus found for blobHash: %s",
				status.ContentID.String(), blobSha)
			log.Errorf(err.Error())
			continue
		}
		RemoveRefFromBlobStatus(ctx, blobStatus)
		blobStatus = nil // Potentially deleted
	}
	status.Blobs = make([]string, 0)
}

func updateContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	log.Functionf("updateContentTree for %v", status.ContentID)
	if changed, _ := doUpdateContentTree(ctx, status); changed {
		publishContentTreeStatus(ctx, status)
	}
	updateVolumeStatusFromContentID(ctx, status.ContentID)

	log.Functionf("updateContentTree for %v Done", status.ContentID)
}

func deleteContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	log.Functionf("deleteContentTree for %v", status.ContentID)
	RemoveAllBlobsFromContentTreeStatus(ctx, status, status.Blobs...)
	//We create a reference when we load the blobs. We should remove that reference when we delete the contentTree.
	if err := ctx.casClient.RemoveImage(status.ReferenceID()); err != nil {
		log.Errorf("deleteContentTree: exception while deleting image %s: %s",
			status.RelativeURL, err.Error())
	}
	unpublishContentTreeStatus(ctx, status)
	deleteLatchContentTreeHash(ctx, status.ContentID, uint32(status.GenerationCounter))
	log.Functionf("deleteContentTree for %v Done", status.ContentID)
}
