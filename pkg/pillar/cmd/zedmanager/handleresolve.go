// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// MaybeAddResolveConfig will publish the resolve config for
// container images for which resolution of tags to sha requires
func MaybeAddResolveConfig(ctx *zedmanagerContext, ss *types.StorageStatus) {

	log.Infof("MaybeAddResolveConfig for %s", ss.ImageID)
	resolveConfig := types.ResolveConfig{
		DatastoreID: ss.DatastoreID,
		Name:        ss.Name,
		AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
			types.AppImgObj),
		Counter: ss.PurgeCounter,
	}
	publishResolveConfig(ctx, &resolveConfig)
	log.Infof("MaybeAddResolveConfig for %s Done", ss.ImageID)
}

func publishResolveConfig(ctx *zedmanagerContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Debugf("publishResolveConfig(%s)", key)
	pub := ctx.pubAppImgResolveConfig
	pub.Publish(key, *config)
	log.Debugf("publishResolveConfig(%s) Done", key)
}

func unpublishResolveConfig(ctx *zedmanagerContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Debugf("unpublishResolveConfig(%s)", key)
	pub := ctx.pubAppImgResolveConfig
	pub.Unpublish(key)
	log.Debugf("unpublishResolveConfig(%s) Done", key)
}

func lookupResolveConfig(ctx *zedmanagerContext,
	key string) *types.ResolveConfig {

	log.Infof("lookupResolveConfig(%s)", key)
	pub := ctx.pubAppImgResolveConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupResolveConfig(%s) not found", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	log.Infof("lookupResolveConfig(%s) Done", key)
	return &config
}

func lookupResolveStatus(ctx *zedmanagerContext,
	key string) *types.ResolveStatus {

	log.Infof("lookupResolveStatus(%s)", key)
	sub := ctx.subAppImgResolveStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupResolveStatus(%s) not found", key)
		return nil
	}
	status := c.(types.ResolveStatus)
	log.Infof("lookupResolveStatus(%s) Done", key)
	return &status
}

func deleteResolveConfig(ctx *zedmanagerContext, key string) {
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
	ctx := ctxArg.(*zedmanagerContext)
	rs := statusArg.(types.ResolveStatus)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		update := false
		status := st.(types.AppInstanceStatus)
		config := lookupAppInstanceConfig(ctx, status.Key())
		if config == nil {
			errStr := fmt.Sprintf("App Instance config not found for %s while resolving tags\n",
				status.Key())
			log.Error(errStr)
			status.SetError(errStr, time.Now())
			publishAppInstanceStatus(ctx, &status)
			continue
		}
		for i := range status.StorageStatusList {
			ss := &status.StorageStatusList[i]
			if !ss.HasResolverRef || ss.Name != rs.Name || ss.DatastoreID != rs.DatastoreID {
				continue
			}
			update = true
		}
		if !update {
			continue
		}
		log.Infof("Updating images SHA for app instance %v",
			status.UUIDandVersion.UUID)
		changed := doUpdate(ctx, *config, &status)
		if changed {
			log.Infof("AppInstance(Name:%s, UUID:%s): handleResolveStatusModify status change.",
				config.DisplayName, config.UUIDandVersion.UUID)
			publishAppInstanceStatus(ctx, &status)
		}
	}
	log.Infof("handleResolveStatusModify done for %s", key)
}
