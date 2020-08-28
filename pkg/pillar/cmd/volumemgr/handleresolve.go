// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MaybeAddResolveConfig will publish the resolve config for
// container images for which resolution of tags to sha requires
func MaybeAddResolveConfig(ctx *volumemgrContext, cs types.ContentTreeStatus) {

	log.Infof("MaybeAddResolveConfig for %s", cs.ContentID)
	resolveConfig := types.ResolveConfig{
		DatastoreID: cs.DatastoreID,
		Name:        cs.RelativeURL,
		AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
			cs.ObjType),
		Counter: uint32(cs.GenerationCounter),
	}
	publishResolveConfig(ctx, &resolveConfig)
	log.Infof("MaybeAddResolveConfig for %s Done", cs.ContentID)
}

func publishResolveConfig(ctx *volumemgrContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Debugf("publishResolveConfig(%s)", key)
	pub := ctx.pubResolveConfig
	pub.Publish(key, *config)
	log.Debugf("publishResolveConfig(%s) Done", key)
}

func unpublishResolveConfig(ctx *volumemgrContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Debugf("unpublishResolveConfig(%s)", key)
	pub := ctx.pubResolveConfig
	pub.Unpublish(key)
	log.Debugf("unpublishResolveConfig(%s) Done", key)
}

func lookupResolveConfig(ctx *volumemgrContext,
	key string) *types.ResolveConfig {

	log.Debugf("lookupResolveConfig(%s)", key)
	pub := ctx.pubResolveConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Debugf("lookupResolveConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	log.Debugf("lookupResolveConfig(%s) Done", key)
	return &config
}

func lookupResolveStatus(ctx *volumemgrContext,
	key string) *types.ResolveStatus {

	log.Debugf("lookupResolveStatus(%s)", key)
	sub := ctx.subResolveStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Debugf("lookupResolveStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ResolveStatus)
	log.Debugf("lookupResolveStatus(%s) Done", key)
	return &status
}

func deleteResolveConfig(ctx *volumemgrContext, key string) {
	log.Infof("deleteResolveConfig for %s", key)
	rc := lookupResolveConfig(ctx, key)
	if rc != nil {
		log.Infof("deleteResolveConfig for %s found", key)
		unpublishResolveConfig(ctx, rc)
	}
	log.Infof("deleteResolveConfig for %s Done", key)
}

func handleResolveStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleResolveStatusModify for %s", key)
	ctx := ctxArg.(*volumemgrContext)
	rs := statusArg.(types.ResolveStatus)
	pub := ctx.pubContentTreeStatus
	items := pub.GetAll()
	for _, cs := range items {
		status := cs.(types.ContentTreeStatus)
		if !status.HasResolverRef ||
			status.RelativeURL != rs.Name ||
			status.DatastoreID != rs.DatastoreID {
			continue
		}
		log.Infof("Updating SHA for content tree: %v",
			status.ContentID)
		changed, _ := doUpdateContentTree(ctx, &status)
		if changed {
			log.Infof("ContentTree(Name:%s, UUID:%s): handleResolveStatusModify status change.",
				status.DisplayName, status.ContentID)
			publishContentTreeStatus(ctx, &status)
		}
		updateVolumeStatusFromContentID(ctx, status.ContentID)
	}
	log.Infof("handleResolveStatusModify done for %s", key)
}
