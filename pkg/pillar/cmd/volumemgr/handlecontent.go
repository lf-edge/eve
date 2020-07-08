// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"strings"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func handleContentTreeCreateAppImg(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeCreateAppImg(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := createContentTreeStatus(ctx, config, types.AppImgObj)
	updateContentTree(ctx, status)
	log.Infof("handleContentTreeCreateAppImg(%s) Done", key)
}

func handleContentTreeModifyAppImg(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeModify(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.AppImgObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	updateContentTree(ctx, status)
	log.Infof("handleContentTreeModify(%s) Done", key)
}

func handleContentTreeDeleteAppImg(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeDelete(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.AppImgObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	deleteContentTree(ctx, status)
	log.Infof("handleContentTreeModify(%s) Done", key)
}

func handleContentTreeCreateBaseOs(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeCreateBaseOs(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := createContentTreeStatus(ctx, config, types.BaseOsObj)
	updateContentTree(ctx, status)
	log.Infof("handleContentTreeCreateBaseOs(%s) Done", key)
}

func handleContentTreeModifyBaseOs(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeModify(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.BaseOsObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	updateContentTree(ctx, status)
	log.Infof("handleContentTreeModify(%s) Done", key)
}

func handleContentTreeDeleteBaseOs(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeDelete(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	status := lookupContentTreeStatus(ctx, config.Key(), types.BaseOsObj)
	if status == nil {
		log.Fatalf("Missing ContentTreeStatus for %s", config.Key())
	}
	deleteContentTree(ctx, status)
	log.Infof("handleContentTreeModify(%s) Done", key)
}

func publishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Debugf("publishContentTreeStatus(%s)", key)
	pub := ctx.publication(types.ContentTreeStatus{}, status.ObjType)
	pub.Publish(key, *status)
	log.Debugf("publishContentTreeStatus(%s) Done", key)
}

func unpublishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Debugf("unpublishContentTreeStatus(%s)", key)
	pub := ctx.publication(types.ContentTreeStatus{}, status.ObjType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishContentTreeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishContentTreeStatus(%s) Done", key)
}

func lookupContentTreeStatus(ctx *volumemgrContext,
	key, objType string) *types.ContentTreeStatus {

	log.Infof("lookupContentTreeStatus(%s/%s)", key, objType)
	pub := ctx.publication(types.ContentTreeStatus{}, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupContentTreeStatus(%s/%s) not found", key, objType)
		return nil
	}
	status := c.(types.ContentTreeStatus)
	log.Infof("lookupContentTreeStatus(%s/%s) Done", key, objType)
	return &status
}

func lookupContentTreeConfig(ctx *volumemgrContext,
	key, objType string) *types.ContentTreeConfig {

	log.Infof("lookupContentTreeConfig(%s/%s)", key, objType)
	sub := ctx.subscription(types.ContentTreeConfig{}, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupContentTreeConfig(%s/%s) not found", key, objType)
		return nil
	}
	config := c.(types.ContentTreeConfig)
	log.Infof("lookupContentTreeConfig(%s/%s) Done", key, objType)
	return &config
}

func createContentTreeStatus(ctx *volumemgrContext, config types.ContentTreeConfig,
	objType string) *types.ContentTreeStatus {

	log.Infof("createContentTreeStatus for %v objType %s", config.ContentID, objType)
	status := lookupContentTreeStatus(ctx, config.Key(), objType)
	if status == nil {
		status = &types.ContentTreeStatus{
			ContentID:         config.ContentID,
			DatastoreID:       config.DatastoreID,
			RelativeURL:       config.RelativeURL,
			Format:            config.Format,
			ContentSha256:     config.ContentSha256,
			MaxDownloadSize:   config.MaxDownloadSize,
			GenerationCounter: config.GenerationCounter,
			ImageSignature:    config.ImageSignature,
			SignatureKey:      config.SignatureKey,
			CertificateChain:  config.CertificateChain,
			DisplayName:       config.DisplayName,
			ObjType:           objType,
			State:             types.INITIAL,
			Blobs:             []string{},
		}

		// we only publish the BlobStatus if we have the hash for it; this
		// might come later
		if config.ContentSha256 != "" {
			status.Blobs = append(status.Blobs, config.ContentSha256)
			sv := SignatureVerifier{
				Signature:        config.ImageSignature,
				PublicKey:        config.SignatureKey,
				CertificateChain: config.CertificateChain,
			}
			if lookupOrCreateBlobStatus(ctx, sv, config.ContentSha256) == nil {
				blobType := types.BlobBinary
				if config.Format == zconfig.Format_CONTAINER {
					blobType = types.BlobUnknown
				}
				rootBlob := &types.BlobStatus{
					DatastoreID: config.DatastoreID,
					RelativeURL: config.RelativeURL,
					Sha256:      strings.ToLower(config.ContentSha256),
					Size:        config.MaxDownloadSize,
					State:       types.INITIAL,
					BlobType:    blobType,
				}
				publishBlobStatus(ctx, rootBlob)
			}
		}
	}
	publishContentTreeStatus(ctx, status)
	log.Infof("createContentTreeStatus for %v Done", config.ContentID)
	return status
}

func updateContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	log.Infof("updateContentTree for %v", status.ContentID)
	if changed, _ := doUpdateContentTree(ctx, status); changed {
		publishContentTreeStatus(ctx, status)
	}
	updateVolumeStatusFromContentID(ctx, status.ContentID)

	log.Infof("updateContentTree for %v Done", status.ContentID)
}

func deleteContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	log.Infof("deleteContentTree for %v", status.ContentID)
	unpublishContentTreeStatus(ctx, status)
	deleteLatchContentTreeHash(ctx, status.ContentID, uint32(status.GenerationCounter))
	log.Infof("deleteContentTree for %v Done", status.ContentID)
}
