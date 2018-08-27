// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"reflect"
)

func MaybeAddAppNetworkConfig(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig, aiStatus *types.AppInstanceStatus) {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Printf("MaybeAddAppNetworkConfig for %s displayName %s\n", key,
		displayName)

	changed := false
	m := lookupAppNetworkConfig(ctx, key)
	if m != nil {
		log.Printf("appNetwork config already exists for %s\n", key)
		if len(aiConfig.OverlayNetworkList) != len(m.OverlayNetworkList) {
			log.Println("Unsupported: Changed number of overlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		if len(aiConfig.UnderlayNetworkList) != len(m.UnderlayNetworkList) {
			log.Println("Unsupported: Changed number of underlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		for i, new := range aiConfig.OverlayNetworkList {
			old := m.OverlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Printf("Over ACLs changed from %v to %v\n",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
		}
		for i, new := range aiConfig.UnderlayNetworkList {
			old := m.UnderlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Printf("Under ACLs changed from %v to %v\n",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
		}
	} else {
		if debug {
			log.Printf("appNetwork config add for %s\n", key)
		}
		changed = true
	}
	if changed {
		nc := types.AppNetworkConfig{
			UUIDandVersion: aiConfig.UUIDandVersion,
			DisplayName:    aiConfig.DisplayName,
			IsZedmanager:   false,
		}
		nc.OverlayNetworkList = make([]types.OverlayNetworkConfig,
			len(aiStatus.EIDList))
		for i, ols := range aiStatus.EIDList {
			olc := &aiConfig.OverlayNetworkList[i]
			ol := &nc.OverlayNetworkList[i]
			// XXX ol.IID = ols.IID
			ol.EID = ols.EID
			ol.LispSignature = ols.LispSignature
			ol.ACLs = olc.ACLs
			// XXX ol.NameToEidList = olc.NameToEidList
			// XXX Default is to use the device list? Need device
			// config for that.
			// XXX ol.LispServers = olc.LispServers
			ol.AppMacAddr = olc.AppMacAddr
			ol.Network = olc.Network
		}
		nc.UnderlayNetworkList = make([]types.UnderlayNetworkConfig,
			len(aiConfig.UnderlayNetworkList))
		for i, ulc := range aiConfig.UnderlayNetworkList {
			ul := &nc.UnderlayNetworkList[i]
			*ul = ulc
		}
		publishAppNetworkConfig(ctx, &nc)
	}
	log.Printf("MaybeAddAppNetworkConfig done for %s\n", key)
}

func lookupAppNetworkConfig(ctx *zedmanagerContext, key string) *types.AppNetworkConfig {

	pub := ctx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("lookupAppNetworkConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastAppNetworkConfig(c)
	if config.Key() != key {
		log.Printf("lookupAppNetworkConfig key/UUID mismatch %s vs %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupAppNetworkStatus(ctx *zedmanagerContext, key string) *types.AppNetworkStatus {
	sub := ctx.subAppNetworkStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Printf("lookupAppNetworkStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastAppNetworkStatus(st)
	if status.Key() != key {
		log.Printf("lookupAppNetworkStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishAppNetworkConfig(ctx *zedmanagerContext,
	status *types.AppNetworkConfig) {

	key := status.Key()
	log.Printf("publishAppNetworkConfig(%s)\n", key)
	pub := ctx.pubAppNetworkConfig
	pub.Publish(key, status)
}

func unpublishAppNetworkConfig(ctx *zedmanagerContext, uuidStr string) {

	key := uuidStr
	log.Printf("unpublishAppNetworkConfig(%s)\n", key)
	pub := ctx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("unpublishAppNetworkConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppNetworkStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := cast.CastAppNetworkStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	log.Printf("handleAppNetworkStatusModify for %s\n", key)
	if status.Key() != key {
		log.Printf("handleAppNetworkStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Printf("handleAppNetworkStatusModify skipped due to Pending* for %s\n",
			key)
		return
	}
	if status.IsZedmanager {
		log.Printf("Ignoring IsZedmanager appNetwork status for %v\n",
			key)
		return
	}
	updateAIStatusUUID(ctx, status.Key())

	log.Printf("handleAppNetworkStatusModify done for %s\n",
		key)
}

func handleAppNetworkStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleAppNetworkStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Printf("handleAppNetworkStatusDelete done for %s\n", key)
}
