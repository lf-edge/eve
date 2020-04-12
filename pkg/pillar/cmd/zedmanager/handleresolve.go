// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func publishResolveConfig(ctx *zedmanagerContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Debugf("publishResolveConfig(%s)\n", key)
	pub := ctx.pubAppImgResolveConfig
	pub.Publish(key, *config)
	log.Debugf("publishResolveConfig(%s) Done\n", key)
}

func unpublishResolveConfig(ctx *zedmanagerContext,
	config *types.ResolveConfig) {

	key := config.Key()
	log.Debugf("unpublishResolveConfig(%s)\n", key)
	pub := ctx.pubAppImgResolveConfig
	pub.Unpublish(key)
	log.Debugf("unpublishResolveConfig(%s) Done\n", key)
}

func lookupResolveConfig(ctx *zedmanagerContext,
	key string) *types.ResolveConfig {

	log.Infof("lookupResolveConfig(%s)\n", key)
	pub := ctx.pubAppImgResolveConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupResolveConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.ResolveConfig)
	log.Infof("lookupResolveConfig(%s) Done\n", key)
	return &config
}

func lookupResolveStatus(ctx *zedmanagerContext,
	key string) *types.ResolveStatus {

	log.Infof("lookupResolveStatus(%s)\n", key)
	sub := ctx.subAppImgResolveStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupResolveStatus(%s) not found\n", key)
		return nil
	}
	status := c.(types.ResolveStatus)
	log.Infof("lookupResolveStatus(%s) Done\n", key)
	return &status
}

func handleResolveStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleResolveStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.ResolveStatus)
	config := lookupResolveConfig(ctx, status.Key())
	if config != nil {
		log.Infof("handleResolveStatusDelete delete config for %s\n",
			key)
		unpublishResolveConfig(ctx, config)
	}
	log.Infof("handleResolveStatusDelete done for %s\n", key)
}

func handleResolveStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleResolveStatusModify for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	rs := statusArg.(types.ResolveStatus)
	pub := ctx.pubAppInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppInstanceStatus)
		config := lookupAppInstanceConfig(ctx, status.Key())
		if config == nil {
			errStr := fmt.Sprintf("App Instance config not found for %s while resolving tags\n",
				status.Key())
			log.Errorf(errStr)
			status.SetError(errStr, agentName, time.Now())
			publishAppInstanceStatus(ctx, &status)
			continue
		}
		for i := range status.StorageStatusList {
			ss := &status.StorageStatusList[i]
			if !ss.HasResolverRef || ss.Name != rs.Name || ss.DatastoreID != rs.DatastoreID {
				continue
			}
			log.Infof("Updating SHA of storage status (%v) in app instance (%v)\n",
				ss.ImageID, status.UUIDandVersion.UUID)
			if len(rs.Error) != 0 {
				errStr := fmt.Sprintf("Error occurred while resolving tags, updating app instance %s.\n",
					status.Key())
				log.Errorf(errStr)
				status.SetError(rs.Error, rs.ErrorSource, rs.ErrorTime)
				publishAppInstanceStatus(ctx, &status)
				continue
			}
			if rs.ImageSha256 == "" {
				errStr := fmt.Sprintf("Empty SHA in resolve status, updating app instance %s.\n",
					status.Key())
				log.Errorf(errStr)
				status.SetError(errStr, agentName, time.Now())
				publishAppInstanceStatus(ctx, &status)
				continue
			}
			sc := lookupStorageConfig(config, *ss)
			if sc == nil {
				errStr := fmt.Sprintf("Storage config (%v) not found for app instance (%s) while resolving tags\n",
					ss.ImageID, status.Key())
				log.Errorf(errStr)
				status.SetError(errStr, agentName, time.Now())
				publishAppInstanceStatus(ctx, &status)
				continue
			}
			if ss.ImageSha256 == "" {
				log.Infof("Image SHA (%s) found while resolving status for storage status (%s)\n",
					rs.ImageSha256, ss.ImageID)
				ss.ImageSha256 = rs.ImageSha256
			} else if ss.ImageSha256 != rs.ImageSha256 {
				log.Infof("Image SHA changed from (%s) to (%s) while resolving status for storage status (%s)\n",
					ss.ImageSha256, rs.ImageSha256, ss.ImageID)
				MaybeRemoveStorageStatus(ctx, status.UUIDandVersion.UUID, ss)
				deleteAppAndImageHash(ctx, status.UUIDandVersion.UUID,
					ss.ImageID)
				ss.UpdateFromStorageConfig(*sc)
				ss.ImageSha256 = rs.ImageSha256
			} else {
				log.Infof("Image SHA (%s) not changed for storage status (%s)\n",
					ss.ImageSha256, ss.ImageID)
			}
			addAppAndImageHash(ctx, config.UUIDandVersion.UUID,
				ss.ImageID, ss.ImageSha256)
			rc := lookupResolveConfig(ctx, rs.Key())
			if rc != nil {
				unpublishResolveConfig(ctx, rc)
			}
			maybeLatchImageSha(ctx, *config, ss)
			ss.HasResolverRef = false
			publishAppInstanceStatus(ctx, &status)
		}
		changed := doUpdate(ctx, *config, &status)
		if changed {
			log.Infof("AppInstance(Name:%s, UUID:%s): handleResolveStatusModify status change.",
				config.DisplayName, config.UUIDandVersion.UUID)
			publishAppInstanceStatus(ctx, &status)
		}
		log.Infof("Updating images SHA for app instance %v Done\n",
			status.UUIDandVersion.UUID)
	}
	log.Infof("handleResolveStatusModify done for %s\n", key)
}
