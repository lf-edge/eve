// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"bytes"
	"reflect"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MaybeAddAppNetworkConfig ensures we have an AppNetworkConfig
func MaybeAddAppNetworkConfig(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig, aiStatus *types.AppInstanceStatus) {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Functionf("MaybeAddAppNetworkConfig for %s displayName %s", key,
		displayName)

	changed := false
	m := lookupAppNetworkConfig(ctx, key)
	if m != nil {
		log.Functionf("appNetwork config already exists for %s", key)
		if len(aiConfig.UnderlayNetworkList) != len(m.UnderlayNetworkList) {
			log.Errorln("Unsupported: Changed number of underlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		if m.Activate != aiConfig.Activate {
			log.Functionf("MaybeAddAppNetworkConfig Activate changed from %v to %v",
				m.Activate, aiConfig.Activate)
			changed = true
		}
		if !m.GetStatsIPAddr.Equal(aiConfig.CollectStatsIPAddr) {
			log.Functionf("MaybeAddAppNetworkConfig: stats ip changed from  %s to %s",
				m.GetStatsIPAddr.String(), aiConfig.CollectStatsIPAddr.String())
			changed = true
		}
		if m.MetaDataType != aiConfig.MetaDataType {
			log.Functionf("MaybeAddAppNetworkConfig: MetaDataType changed from  %s to %s",
				m.MetaDataType.String(), aiConfig.MetaDataType.String())
			changed = true
		}
		if m.CloudInitUserData != aiConfig.CloudInitUserData {
			log.Functionf("MaybeAddAppNetworkConfig: CloudInitUserData changed")
			changed = true
		}
		if bytes.Compare(m.CipherBlockStatus.CipherData, aiConfig.CipherBlockStatus.CipherData) != 0 {
			log.Functionf("MaybeAddAppNetworkConfig: CipherBlockStatus.CipherData changed")
			changed = true
		}
		for i, new := range aiConfig.UnderlayNetworkList {
			old := m.UnderlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Functionf("Under ACLs changed from %v to %v",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
		}
	} else {
		log.Tracef("appNetwork config add for %s", key)
		changed = true
	}
	if changed {
		nc := types.AppNetworkConfig{
			UUIDandVersion:    aiConfig.UUIDandVersion,
			DisplayName:       aiConfig.DisplayName,
			Activate:          aiConfig.Activate,
			GetStatsIPAddr:    aiConfig.CollectStatsIPAddr,
			CloudInitUserData: aiConfig.CloudInitUserData,
			CipherBlockStatus: aiConfig.CipherBlockStatus,
			MetaDataType:      aiConfig.MetaDataType,
		}
		nc.UnderlayNetworkList = make([]types.UnderlayNetworkConfig,
			len(aiConfig.UnderlayNetworkList))
		for i, ulc := range aiConfig.UnderlayNetworkList {
			ul := &nc.UnderlayNetworkList[i]
			*ul = ulc
		}
		publishAppNetworkConfig(ctx, &nc)
	}
	log.Functionf("MaybeAddAppNetworkConfig done for %s", key)
}

func lookupAppNetworkConfig(ctx *zedmanagerContext, key string) *types.AppNetworkConfig {

	pub := ctx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Tracef("lookupAppNetworkConfig(%s) not found", key)
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
		log.Tracef("lookupAppNetworkStatus(%s) not found", key)
		return nil
	}
	status := st.(types.AppNetworkStatus)
	return &status
}

func publishAppNetworkConfig(ctx *zedmanagerContext,
	status *types.AppNetworkConfig) {

	key := status.Key()
	log.Functionf("publishAppNetworkConfig(%s)", key)
	pub := ctx.pubAppNetworkConfig
	pub.Publish(key, *status)
}

func unpublishAppNetworkConfig(ctx *zedmanagerContext, uuidStr string) {

	key := uuidStr
	log.Functionf("unpublishAppNetworkConfig(%s)", key)
	pub := ctx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishAppNetworkConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func handleAppNetworkStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppNetworkStatusImpl(ctxArg, key, statusArg)
}

func handleAppNetworkStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppNetworkStatusImpl(ctxArg, key, statusArg)
}

func handleAppNetworkStatusImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.AppNetworkStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Functionf("handleAppNetworkStatusModify: key:%s, name:%s",
		key, status.DisplayName)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Functionf("skipped AppNetworkConfigModify due to Pending* "+
			"(Add:%t, Modify:%t, Del:%t) for %s:%s", status.PendingAdd,
			status.PendingModify, status.PendingDelete, status.DisplayName, key)
		return
	}
	updateAIStatusUUID(ctx, status.Key())
	log.Functionf("handleAppNetworkStatusModify done for %s", key)
}

func handleAppNetworkStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAppNetworkStatusDelete for %s", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusUUID(ctx, key)
	log.Functionf("handleAppNetworkStatusDelete done for %s", key)
}

func updateAppNetworkStatus(aiStatus *types.AppInstanceStatus,
	ns *types.AppNetworkStatus) {

	aiStatus.UnderlayNetworks = ns.UnderlayNetworkList
}
