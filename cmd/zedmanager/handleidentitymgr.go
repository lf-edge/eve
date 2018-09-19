// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
)

func MaybeAddEIDConfig(ctx *zedmanagerContext,
	UUIDandVersion types.UUIDandVersion,
	displayName string, ec *types.EIDOverlayConfig) {

	key := types.EidKey(UUIDandVersion, ec.IID)
	log.Printf("MaybeAddEIDConfig for %s displayName %s\n", key,
		displayName)

	m := lookupEIDConfig(ctx, key)
	if m != nil {
		log.Printf("EID config already exists for %s\n", key)
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
	log.Printf("MaybeAddEIDConfig done for %s\n", key)
}

func lookupEIDConfig(ctx *zedmanagerContext, key string) *types.EIDConfig {

	pub := ctx.pubEIDConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("lookupEIDConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastEIDConfig(c)
	if config.Key() != key {
		log.Printf("lookupEIDConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupEIDStatus(ctx *zedmanagerContext, key string) *types.EIDStatus {
	sub := ctx.subEIDStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Printf("lookupEIDStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastEIDStatus(st)
	if status.Key() != key {
		log.Printf("lookupEIDStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishEIDConfig(ctx *zedmanagerContext,
	status *types.EIDConfig) {

	key := status.Key()
	log.Printf("publishEIDConfig(%s)\n", key)
	pub := ctx.pubEIDConfig
	pub.Publish(key, status)
}

func unpublishEIDConfig(ctx *zedmanagerContext, uuidAndVers types.UUIDandVersion,
	es *types.EIDStatusDetails) {

	key := types.EidKey(uuidAndVers, es.IID)
	log.Printf("unpublishEIDConfig(%s)\n", key)
	pub := ctx.pubEIDConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("unpublishEIDConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleEIDStatusModify(ctxArg interface{}, keyArg string,
	statusArg interface{}) {
	status := cast.CastEIDStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	key := status.Key()
	log.Printf("handleEIDStatusModify for %s\n", key)
	if key != keyArg {
		log.Printf("handleEIDModify key/UUID mismatch %s vs %s; ignored %+v\n",
			keyArg, key, status)
		return
	}
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Printf("handleEIDStatusModify skipping due to Pending* for %s\n",
			key)
		return
	}
	updateAIStatusUUID(ctx, status.UUIDandVersion.UUID.String())
	log.Printf("handleEIDStatusModify done for %s\n", key)
}

func handleEIDStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleEIDStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Printf("handleEIDStatusDelete done for %s\n", key)
}
