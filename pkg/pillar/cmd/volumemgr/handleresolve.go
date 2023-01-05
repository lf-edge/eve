// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MaybeAddResolveConfig will publish the resolve config for
// container images for which resolution of tags to sha requires
func MaybeAddResolveConfig(ctx *volumemgrContext, cs types.ContentTreeStatus) {

	log.Functionf("MaybeAddResolveConfig for %s", cs.ContentID)
	resolveConfig := types.ResolveConfig{
		DatastoreID: cs.DatastoreIDList[0],
		Name:        cs.RelativeURL,
		Counter:     uint32(cs.GenerationCounter),
	}
	publishResolveConfig(ctx, &resolveConfig)
	log.Functionf("MaybeAddResolveConfig for %s Done", cs.ContentID)
}

func publishResolveConfig(ctx *volumemgrContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Tracef("publishResolveConfig(%s)", key)
	pub := ctx.pubResolveConfig
	pub.Publish(key, *config)
	log.Tracef("publishResolveConfig(%s) Done", key)
}

func unpublishResolveConfig(ctx *volumemgrContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Tracef("unpublishResolveConfig(%s)", key)
	pub := ctx.pubResolveConfig
	pub.Unpublish(key)
	log.Tracef("unpublishResolveConfig(%s) Done", key)
}

func lookupResolveConfig(ctx *volumemgrContext,
	key string) *types.ResolveConfig {

	log.Tracef("lookupResolveConfig(%s)", key)
	pub := ctx.pubResolveConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupResolveConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	log.Tracef("lookupResolveConfig(%s) Done", key)
	return &config
}

func lookupResolveStatus(ctx *volumemgrContext,
	key string) *types.ResolveStatus {

	log.Tracef("lookupResolveStatus(%s)", key)
	sub := ctx.subResolveStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Tracef("lookupResolveStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ResolveStatus)
	log.Tracef("lookupResolveStatus(%s) Done", key)
	return &status
}

func deleteResolveConfig(ctx *volumemgrContext, key string) {
	log.Functionf("deleteResolveConfig for %s", key)
	rc := lookupResolveConfig(ctx, key)
	if rc != nil {
		log.Functionf("deleteResolveConfig for %s found", key)
		unpublishResolveConfig(ctx, rc)
	}
	log.Functionf("deleteResolveConfig for %s Done", key)
}

func handleResolveStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleResolveStatusImpl(ctxArg, key, statusArg)
}

func handleResolveStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleResolveStatusImpl(ctxArg, key, statusArg)
}

func handleResolveStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleResolveStatusImpl for %s", key)
	ctx := ctxArg.(*volumemgrContext)
	rs := statusArg.(types.ResolveStatus)
	pub := ctx.pubContentTreeStatus
	items := pub.GetAll()
	for _, cs := range items {
		status := cs.(types.ContentTreeStatus)
		if !status.HasResolverRef ||
			status.RelativeURL != rs.Name ||
			status.DatastoreIDList[0] != rs.DatastoreID {
			continue
		}
		log.Functionf("Updating SHA for content tree: %v",
			status.ContentID)
		changed, _ := doUpdateContentTree(ctx, &status)
		if changed {
			log.Functionf("ContentTree(Name:%s, UUID:%s): handleResolveStatusImpl status change.",
				status.DisplayName, status.ContentID)
			publishContentTreeStatus(ctx, &status)
		}
		updateVolumeStatusFromContentID(ctx, status.ContentID)
	}
	log.Functionf("handleResolveStatusImpl done for %s", key)
}
