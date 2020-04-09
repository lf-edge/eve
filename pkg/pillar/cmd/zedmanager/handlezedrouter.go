// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"reflect"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// MaybeAddAppNetworkConfig ensures we have an AppNetworkConfig
func MaybeAddAppNetworkConfig(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig, aiStatus *types.AppInstanceStatus) {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Infof("MaybeAddAppNetworkConfig for %s displayName %s\n", key,
		displayName)

	changed := false
	m := lookupAppNetworkConfig(ctx, key)
	if m != nil {
		log.Infof("appNetwork config already exists for %s\n", key)
		if len(aiConfig.OverlayNetworkList) != len(m.OverlayNetworkList) {
			log.Errorln("Unsupported: Changed number of overlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		if len(aiConfig.UnderlayNetworkList) != len(m.UnderlayNetworkList) {
			log.Errorln("Unsupported: Changed number of underlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		if m.Activate != aiConfig.Activate {
			log.Infof("MaybeAddAppNetworkConfig Activate changed from %v to %v\n",
				m.Activate, aiConfig.Activate)
			changed = true
		}
		for i, new := range aiConfig.OverlayNetworkList {
			old := m.OverlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Infof("Over ACLs changed from %v to %v\n",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
		}
		for i, new := range aiConfig.UnderlayNetworkList {
			old := m.UnderlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Infof("Under ACLs changed from %v to %v\n",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
		}
	} else {
		log.Debugf("appNetwork config add for %s\n", key)
		changed = true
	}
	if changed {
		nc := types.AppNetworkConfig{
			UUIDandVersion: aiConfig.UUIDandVersion,
			DisplayName:    aiConfig.DisplayName,
			IsZedmanager:   false,
			Activate:       aiConfig.Activate,
		}
		nc.OverlayNetworkList = make([]types.OverlayNetworkConfig,
			len(aiStatus.EIDList))
		for i, ols := range aiStatus.EIDList {
			olc := &aiConfig.OverlayNetworkList[i]
			ol := &nc.OverlayNetworkList[i]
			ol.Name = olc.Name
			ol.EID = ols.EID
			ol.LispSignature = ols.LispSignature
			ol.ACLs = olc.ACLs
			ol.AppMacAddr = olc.AppMacAddr
			ol.AppIPAddr = olc.AppIPAddr
			ol.Network = olc.Network
			ol.MgmtIID = ols.IID
		}
		nc.UnderlayNetworkList = make([]types.UnderlayNetworkConfig,
			len(aiConfig.UnderlayNetworkList))
		for i, ulc := range aiConfig.UnderlayNetworkList {
			ul := &nc.UnderlayNetworkList[i]
			*ul = ulc
		}
		publishAppNetworkConfig(ctx, &nc)
	}
	log.Infof("MaybeAddAppNetworkConfig done for %s\n", key)
}

func lookupAppNetworkConfig(ctx *zedmanagerContext, key string) *types.AppNetworkConfig {

	pub := ctx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupAppNetworkConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.AppNetworkConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
func lookupAppNetworkStatus(ctx *zedmanagerContext, key string) *types.AppNetworkStatus {
	sub := ctx.subAppNetworkStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupAppNetworkStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.AppNetworkStatus)
	return &status
}

func publishAppNetworkConfig(ctx *zedmanagerContext,
	status *types.AppNetworkConfig) {

	key := status.Key()
	log.Infof("publishAppNetworkConfig(%s)\n", key)
	pub := ctx.pubAppNetworkConfig
	pub.Publish(key, *status)
}

func unpublishAppNetworkConfig(ctx *zedmanagerContext, uuidStr string) {

	key := uuidStr
	log.Infof("unpublishAppNetworkConfig(%s)\n", key)
	pub := ctx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishAppNetworkConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppNetworkStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.AppNetworkStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleAppNetworkStatusModify: key:%s, name:%s\n",
		key, status.DisplayName)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("skipped AppNetworkConfigModify due to Pending* "+
			"(Add:%t, Modify:%t, Del:%t) for %s:%s\n", status.PendingAdd,
			status.PendingModify, status.PendingDelete, status.DisplayName, key)
		return
	}
	if status.IsZedmanager {
		log.Infof("Ignoring IsZedmanager appNetwork status for %v\n",
			key)
		return
	}
	updateAIStatusUUID(ctx, status.Key())
	log.Infof("handleAppNetworkStatusModify done for %s\n", key)
}

func handleAppNetworkStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleAppNetworkStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Infof("handleAppNetworkStatusDelete done for %s\n", key)
}

func updateAppNetworkStatus(aiStatus *types.AppInstanceStatus,
	ns *types.AppNetworkStatus) {

	aiStatus.OverlayNetworks = ns.OverlayNetworkList
	aiStatus.UnderlayNetworks = ns.UnderlayNetworkList
}
