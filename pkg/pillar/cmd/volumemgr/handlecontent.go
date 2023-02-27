// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"
	"time"

	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/vault"
)

func handleContentTreeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleContentTreeCreate(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	// we received content tree configuration
	// clean of vault is not safe from now
	// note that we wait for vault before start this handler
	if err := vault.DisallowVaultCleanup(); err != nil {
		log.Errorf("cannot disallow vault cleanup: %s", err)
	}
	status := createContentTreeStatus(ctx, config)
	updateContentTree(ctx, status)
	log.Functionf("handleContentTreeCreate(%s) Done", key)
}

func handleContentTreeModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("handleContentTreeModify(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := ctx.LookupContentTreeStatus(config.Key())
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	updateContentTree(ctx, status)
	log.Functionf("handleContentTree(%s) Done", key)
}

func handleContentTreeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("handleContentTreeDelete(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := ctx.LookupContentTreeStatus(config.Key())
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	deleteContentTree(ctx, status)
	log.Functionf("handleContentTreeDelete(%s) Done", key)
}

func handleContentTreeRestart(ctxArg interface{}, restartCounter int) {
	log.Functionf("handleContentTreeRestart(%d)", restartCounter)
	ctx := ctxArg.(*volumemgrContext)
	if restartCounter != 0 {
		ctx.contentTreeRestarted = true
	}
}

func publishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Tracef("publishContentTreeStatus(%s)", key)
	pub := ctx.pubContentTreeStatus
	pub.Publish(key, *status)
	log.Tracef("publishContentTreeStatus(%s) Done", key)
}

func unpublishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Tracef("unpublishContentTreeStatus(%s)", key)
	pub := ctx.pubContentTreeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishContentTreeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishContentTreeStatus(%s) Done", key)
}

// LookupContentTreeStatus returns ContentTreeStatus based on key
func (ctxPtr *volumemgrContext) LookupContentTreeStatus(key string) *types.ContentTreeStatus {
	log.Tracef("lookupContentTreeStatus(%s)", key)
	pub := ctxPtr.pubContentTreeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupContentTreeStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ContentTreeStatus)
	log.Tracef("lookupContentTreeStatus(%s) Done", key)
	return &status
}

func getAllContentTreeStatus(ctx *volumemgrContext) map[string]*types.ContentTreeStatus {
	log.Tracef("getAllContentTreeStatus")
	contentIDAndContentTreeStatus := make(map[string]*types.ContentTreeStatus)

	pub := ctx.pubContentTreeStatus
	allContentTreeStatus := pub.GetAll()
	for key, item := range allContentTreeStatus {
		contentTreeStatus := item.(types.ContentTreeStatus)
		contentIDAndContentTreeStatus[key] = &contentTreeStatus
	}

	log.Tracef("getAllContentTreeStatus: Done")
	return contentIDAndContentTreeStatus
}

func lookupContentTreeConfig(ctx *volumemgrContext, key string) *types.ContentTreeConfig {

	log.Tracef("lookupContentTreeConfig(%s)", key)
	sub := ctx.subContentTreeConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupContentTreeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ContentTreeConfig)
	log.Tracef("lookupContentTreeConfig(%s) Done", key)
	return &config
}

// populateDatastoreFields() - populate all datastore related fields traversing
//
//	all datastore IDs list. Type of the found datastore
//	is stored into the types list. Mark the whole
//	status as resolved if all the datastores were
//	successfully found.
func populateDatastoreFields(ctx *volumemgrContext, config types.ContentTreeConfig,
	status *types.ContentTreeStatus) {

	nr := len(config.DatastoreIDList)
	status.DatastoreTypesList = make([]string, nr)

	nrResolved := 0
	for i, dsid := range config.DatastoreIDList {
		dsConfig, err := utils.LookupDatastoreConfig(ctx.subDatastoreConfig, dsid)
		if dsConfig == nil {
			// Still not found, repeat on the datastore update
			log.Errorf("populateDatastoreFields(%s): datastoreConfig for %s not found %v", config.Key(), dsid, err)
			continue
		}
		status.DatastoreTypesList[i] = dsConfig.DsType
		nrResolved++

		// OCI registry is special, so mark the whole status if there is any
		if dsConfig.DsType == zconfig.DsType_DsContainerRegistry.String() {
			status.IsOCIRegistry = true
		}
	}

	status.AllDatastoresResolved = (nrResolved == nr)
}

func createContentTreeStatus(ctx *volumemgrContext, config types.ContentTreeConfig) *types.ContentTreeStatus {

	log.Functionf("createContentTreeStatus for %v", config.ContentID)
	status := ctx.LookupContentTreeStatus(config.Key())
	if status == nil {
		status = &types.ContentTreeStatus{
			ContentID:         config.ContentID,
			DatastoreIDList:   config.DatastoreIDList,
			RelativeURL:       config.RelativeURL,
			Format:            config.Format,
			ContentSha256:     config.ContentSha256,
			MaxDownloadSize:   config.MaxDownloadSize,
			GenerationCounter: config.GenerationCounter,
			DisplayName:       config.DisplayName,
			State:             types.INITIAL,
			Blobs:             []string{},
			// LastRefCountChangeTime: time.Now(),
		}
		populateDatastoreFields(ctx, config, status)

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
					DatastoreIDList:        config.DatastoreIDList,
					RelativeURL:            config.RelativeURL,
					Sha256:                 strings.ToLower(config.ContentSha256),
					Size:                   config.MaxDownloadSize,
					State:                  types.INITIAL,
					MediaType:              mediaType,
					CreateTime:             time.Now(),
					LastRefCountChangeTime: time.Now(),
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

// AddBlobsToContentTreeStatus adds blob to ContentTreeStatus.Blobs also increments RefCount of the respective BlobStatus.
// NOTE: This should be the only method to add blobs into ContentTreeStatus.Blobs
func AddBlobsToContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus, blobShas ...string) error {
	log.Functionf("AddBlobsToContentTreeStatus(%s): for blobs %v", status.ContentID, blobShas)
	for _, blobSha := range blobShas {
		blobStatus := ctx.LookupBlobStatus(blobSha)
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

// RemoveAllBlobsFromContentTreeStatus removes all the blob from ContentTreeStatus.Blobs also decrements RefCount of the
// respective BlobStatus.
// NOTE: This should be the only method to remove blobs from ContentTreeStatus.Blobs
func RemoveAllBlobsFromContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus, blobShas ...string) {
	log.Functionf("RemoveAllBlobsFromContentTreeStatus(%s): for blobs %v", status.ContentID, blobShas)
	for _, blobSha := range status.Blobs {
		blobStatus := ctx.LookupBlobStatus(blobSha)
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

type timeAndContentTreeStatus struct {
	deleteTime time.Time
	status     *types.ContentTreeStatus
}

// deferredDelete has entries in time order
var deferredDelete = make([]timeAndContentTreeStatus, 0)

// deleteContentTree optionally delays the delete using the above slice
func deleteContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	log.Functionf("deleteContentTree for %v", status.ContentID)

	// Clean up in case it was never resolved
	deleteResolveConfig(ctx, status.ResolveKey())

	// If the content tree did not complete, or knob is at default of
	// no defer, then delete. Otherwise honor defer time to to avoid
	// delete then re-download
	if status.State < types.LOADED || ctx.deferContentDelete == 0 {
		doDeleteContentTree(ctx, status)
	} else {
		expiry := time.Now().Add(time.Duration(ctx.deferContentDelete) * time.Second)
		tc := timeAndContentTreeStatus{
			deleteTime: expiry,
			status:     status,
		}
		log.Noticef("Deferring delete of %s to %v",
			status.Key(), expiry)
		deferredDelete = append(deferredDelete, tc)
	}
}

func checkDeferredDelete(ctx *volumemgrContext) {
	newDD := make([]timeAndContentTreeStatus, 0)
	for _, tc := range deferredDelete {
		if time.Now().After(tc.deleteTime) {
			log.Noticef("Handling deferred delete of %s",
				tc.status.Key())
			doDeleteContentTree(ctx, tc.status)
		} else {
			newDD = append(newDD, tc)
		}
	}
	deferredDelete = newDD
}

func doDeleteContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	log.Functionf("doDeleteContentTree for %v", status.ContentID)
	RemoveAllBlobsFromContentTreeStatus(ctx, status, status.Blobs...)
	//We create a reference when we load the blobs. We should remove that reference when we delete the contentTree.
	if err := ctx.casClient.RemoveImage(status.ReferenceID()); err != nil {
		log.Errorf("doDeleteContentTree: exception while deleting image %s: %s",
			status.RelativeURL, err.Error())
	}
	unpublishContentTreeStatus(ctx, status)
	deleteLatchContentTreeHash(ctx, status.ContentID, uint32(status.GenerationCounter))
	log.Functionf("doDeleteContentTree for %v Done", status.ContentID)
}
