// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"strings"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func handleContentTreeCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeCreate(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	updateContentTree(ctx, config)
	log.Infof("handleContentTreeCreate(%s) Done", key)
}

func handleContentTreeModify(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeModify(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	updateContentTree(ctx, config)
	log.Infof("handleContentTreeModify(%s) Done", key)
}

func handleContentTreeDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Infof("handleContentTreeDelete(%s)", key)
	config := configArg.(types.ContentTreeConfig)
	ctx := ctxArg.(*volumemgrContext)
	deleteContentTree(ctx, config)
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

	log.Infof("lookupContentTreeStatus(%s)", key)
	pub := ctx.publication(types.ContentTreeStatus{}, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupContentTreeStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ContentTreeStatus)
	log.Infof("lookupContentTreeStatus(%s) Done", key)
	return &status
}

func lookupContentTreeConfig(ctx *volumemgrContext,
	key, objType string) *types.ContentTreeConfig {

	log.Infof("lookupContentTreeConfig(%s)", key)
	sub := ctx.subscription(types.ContentTreeConfig{}, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupContentTreeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ContentTreeConfig)
	log.Infof("lookupContentTreeConfig(%s) Done", key)
	return &config
}

func updateContentTree(ctx *volumemgrContext, config types.ContentTreeConfig) {
	log.Infof("updateContentTree for %v", config.ContentID)
	status := lookupContentTreeStatus(ctx, config.Key(), config.ObjType)
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
			ObjType:           config.ObjType,
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
			if lookupOrCreateBlobStatus(ctx, sv, status.ObjType, config.ContentSha256) == nil {
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
					ObjType:     config.ObjType,
				}
				publishBlobStatus(ctx, rootBlob)
			}
		}
	}
	publishContentTreeStatus(ctx, status)
	if changed, _ := doUpdateContentTree(ctx, status); changed {
		publishContentTreeStatus(ctx, status)
	}
	updateVolumeStatusFromContentID(ctx, status.ContentID)

	log.Infof("updateContentTree for %v Done", config.ContentID)
}

func deleteContentTree(ctx *volumemgrContext, config types.ContentTreeConfig) {
	log.Infof("deleteContentTree for %v", config.ContentID)
	status := lookupContentTreeStatus(ctx, config.Key(), config.ObjType)
	if status == nil {
		log.Infof("deleteContentTree for %v, ContentTreeStatus not found", config.ContentID)
		return
	}
	unpublishContentTreeStatus(ctx, status)
	deleteLatchContentTreeHash(ctx, config.ContentID, uint32(config.GenerationCounter))
	log.Infof("deleteContentTree for %v Done", config.ContentID)
}
