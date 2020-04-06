// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func publishResolveConfig(ctx *zedmanagerContext,
	config *types.AppImgResolveConfig) {

	key := config.Key()
	log.Debugf("publishResolveConfig(%s)\n", key)
	pub := ctx.pubAppImgResolveConfig
	pub.Publish(key, *config)
	log.Debugf("publishResolveConfig(%s) Done\n", key)
}

func unpublishResolveConfig(ctx *zedmanagerContext,
	config *types.AppImgResolveConfig) {

	key := config.Key()
	log.Debugf("unpublishResolveConfig(%s)\n", key)
	pub := ctx.pubAppImgResolveConfig
	pub.Unpublish(key)
	log.Debugf("unpublishResolveConfig(%s) Done\n", key)
}

func lookupResolveConfig(ctx *zedmanagerContext,
	key string) *types.AppImgResolveConfig {

	pub := ctx.pubAppImgResolveConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupResolveConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.AppImgResolveConfig)
	return &config
}

func lookupResolveStatus(ctx *zedmanagerContext,
	key string) *types.AppImgResolveStatus {

	sub := ctx.subAppImgResolveStatus
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupResolveStatus(%s) not found\n", key)
		return nil
	}
	status := c.(types.AppImgResolveStatus)
	return &status
}

func handleResolveStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleResolveStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := statusArg.(types.AppImgResolveStatus)
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

	return
}
