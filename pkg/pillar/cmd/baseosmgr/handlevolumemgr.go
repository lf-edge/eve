// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

// Code for the interface with VolumeMgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MaybeAddContentTreeConfig makes sure we have a ContentTreeConfig
func MaybeAddContentTreeConfig(ctx *baseOsMgrContext, ctc *types.ContentTreeConfig) bool {
	log.Functionf("MaybeAddContentTreeConfig for %s", ctc.Key())
	m := lookupContentTreeConfig(ctx, ctc.Key())
	if m != nil {
		log.Functionf("Content tree config exists for %s", ctc.Key())
		return false
	}
	publishContentTreeConfig(ctx, ctc)
	log.Functionf("MaybeAddContentTreeConfig for %s Done", ctc.Key())
	return true
}

// MaybeRemoveContentTreeConfig deletes the ContentTreeConfig
func MaybeRemoveContentTreeConfig(ctx *baseOsMgrContext, key string) bool {
	log.Functionf("MaybeRemoveContentTreeConfig for %s", key)
	m := lookupContentTreeConfig(ctx, key)
	if m == nil {
		log.Functionf("MaybeRemoveContentTreeConfig: config doesn't exist for %s", key)
		return false
	}
	unpublishContentTreeConfig(ctx, key)
	log.Functionf("MaybeRemoveContentTreeConfig for %s Done", key)
	return true
}

func lookupContentTreeConfig(ctx *baseOsMgrContext, key string) *types.ContentTreeConfig {

	pub := ctx.pubContentTreeConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Functionf("lookupContentTreeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ContentTreeConfig)
	return &config
}

func lookupContentTreeStatus(ctx *baseOsMgrContext, key string) *types.ContentTreeStatus {

	sub := ctx.subContentTreeStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Functionf("lookupContentTreeStatus(%s) not found", key)
		return nil
	}
	status := st.(types.ContentTreeStatus)
	return &status
}

func publishContentTreeConfig(ctx *baseOsMgrContext, config *types.ContentTreeConfig) {

	key := config.Key()
	log.Functionf("publishContentTreeConfig(%s)", key)
	pub := ctx.pubContentTreeConfig
	pub.Publish(key, *config)
}

func unpublishContentTreeConfig(ctx *baseOsMgrContext, key string) {

	log.Functionf("unpublishContentTreeConfig(%s)", key)
	pub := ctx.pubContentTreeConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishContentTreeConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func handleContentTreeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleContentTreeStatusImpl(ctxArg, key, statusArg)
}

func handleContentTreeStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.ContentTreeStatus)
	ctx := ctxArg.(*baseOsMgrContext)
	log.Functionf("handleContentTreeStatusImpl: key:%s, name:%s",
		key, status.DisplayName)
	if status.ContentSha256 != "" {
		baseOsHandleStatusUpdateImageSha(ctx, status.ContentSha256)
	} else {
		log.Warnf("Unknown content tree: %s", status.ContentID.String())
	}
	log.Functionf("handleContentTreeStatusImpl done for %s", key)
}

func handleContentTreeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleContentTreeStatusDelete for %s", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := statusArg.(types.ContentTreeStatus)
	if status.ContentSha256 != "" {
		baseOsHandleStatusUpdateImageSha(ctx, status.ContentSha256)
	} else {
		log.Warnf("Unknown content tree: %s", status.ContentID.String())
	}
	log.Functionf("handleContentTreeStatusDelete done for %s", key)
}
