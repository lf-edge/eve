// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func MaybeAddEIDConfig(ctx *zedmanagerContext,
	UUIDandVersion types.UUIDandVersion,
	displayName string, ec *types.EIDOverlayConfig) {

	key := types.EidKey(UUIDandVersion, ec.IID)
	log.Infof("MaybeAddEIDConfig for %s displayName %s\n", key,
		displayName)

	m := lookupEIDConfig(ctx, key)
	if m != nil {
		log.Infof("EID config already exists for %s\n", key)
		// XXX check displayName and EIDConfigDetails didn't change?
	} else {
		log.Debugf("EID config add for %s\n", key)
		config := types.EIDConfig{
			UUIDandVersion:   UUIDandVersion,
			DisplayName:      displayName,
			EIDConfigDetails: ec.EIDConfigDetails,
		}
		publishEIDConfig(ctx, &config)
	}
	log.Infof("MaybeAddEIDConfig done for %s\n", key)
}

func lookupEIDConfig(ctx *zedmanagerContext, key string) *types.EIDConfig {

	pub := ctx.pubEIDConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupEIDConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.EIDConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupEIDStatus(ctx *zedmanagerContext, key string) *types.EIDStatus {
	sub := ctx.subEIDStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupEIDStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.EIDStatus)
	return &status
}

func publishEIDConfig(ctx *zedmanagerContext,
	status *types.EIDConfig) {

	key := status.Key()
	log.Debugf("publishEIDConfig(%s)\n", key)
	pub := ctx.pubEIDConfig
	pub.Publish(key, *status)
}

func unpublishEIDConfig(ctx *zedmanagerContext, uuidAndVers types.UUIDandVersion,
	es *types.EIDStatusDetails) {

	key := types.EidKey(uuidAndVers, es.IID)
	log.Debugf("unpublishEIDConfig(%s)\n", key)
	pub := ctx.pubEIDConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishEIDConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleEIDStatusModify(ctxArg interface{}, keyArg string,
	statusArg interface{}) {
	status := statusArg.(types.EIDStatus)
	ctx := ctxArg.(*zedmanagerContext)
	key := status.Key()
	log.Infof("handleEIDStatusModify for %s\n", key)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("handleEIDStatusModify skipping due to Pending* for %s\n",
			key)
		return
	}
	updateAIStatusUUID(ctx, status.UUIDandVersion.UUID.String())
	log.Infof("handleEIDStatusModify done for %s\n", key)
}

func handleEIDStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleEIDStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Infof("handleEIDStatusDelete done for %s\n", key)
}
