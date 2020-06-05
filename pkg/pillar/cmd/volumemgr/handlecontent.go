// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
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
	pub := ctx.pubContentTreeStatus
	pub.Publish(key, *status)
	log.Debugf("publishContentTreeStatus(%s) Done", key)
}

func unpublishContentTreeStatus(ctx *volumemgrContext, status *types.ContentTreeStatus) {

	key := status.Key()
	log.Debugf("unpublishContentTreeStatus(%s)", key)
	pub := ctx.pubContentTreeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishContentTreeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishContentTreeStatus(%s) Done", key)
}

func lookupContentTreeStatus(ctx *volumemgrContext,
	key string) *types.ContentTreeStatus {

	log.Infof("lookupContentTreeStatus(%s)", key)
	pub := ctx.pubContentTreeStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupContentTreeStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ContentTreeStatus)
	log.Infof("lookupContentTreeStatus(%s) Done", key)
	return &status
}

func updateContentTree(ctx *volumemgrContext, config types.ContentTreeConfig) {
	log.Infof("updateContentTree for %v", config.ContentID)
	status := lookupContentTreeStatus(ctx, config.Key())
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
			ObjType:           types.AppImgObj,
		}
	}
	publishContentTreeStatus(ctx, status)
	changed, _ := doUpdateCT(ctx, status)
	if changed {
		publishContentTreeStatus(ctx, status)
	}
	log.Infof("updateContentTree for %v Done", config.ContentID)
}

func deleteContentTree(ctx *volumemgrContext, config types.ContentTreeConfig) {
	log.Infof("deleteContentTree for %v", config.ContentID)
	status := lookupContentTreeStatus(ctx, config.Key())
	if status == nil {
		log.Infof("deleteContentTree for %v, ContentTreeStatus not found", config.ContentID)
		return
	}
	changed := false
	if status.HasDownloaderRef {
		MaybeRemoveDownloaderConfig(ctx, status.ObjType,
			status.ContentSha256)
		status.HasDownloaderRef = false
		changed = true
	}
	if status.HasVerifierRef {
		MaybeRemoveVerifyImageConfig(ctx, status.ObjType,
			status.ContentSha256)
		status.HasVerifierRef = false
		changed = true
	}
	if status.HasPersistRef {
		ReduceRefCountPersistImageStatus(ctx, status.ObjType, status.ContentSha256)
		status.HasPersistRef = false
		changed = true
	}
	if changed {
		publishContentTreeStatus(ctx, status)
	}
	unpublishContentTreeStatus(ctx, status)
	deleteLatchContentTreeHash(ctx, config.ContentID, uint32(config.GenerationCounter))
	log.Infof("deleteContentTree for %v Done", config.ContentID)
}
