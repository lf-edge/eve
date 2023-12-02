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

	effectiveActivate := effectiveActivateCurrentProfile(aiConfig, ctx.currentProfile)

	changed := false
	m := lookupAppNetworkConfig(ctx, key)
	if m != nil {
		log.Functionf("appNetwork config already exists for %s", key)
		if len(aiConfig.AppNetAdapterList) != len(m.AppNetAdapterList) {
			log.Errorln("Unsupported: Changed number of AppNetAdapter for ",
				aiConfig.UUIDandVersion)
			return
		}
		if m.Activate != effectiveActivate {
			log.Functionf("MaybeAddAppNetworkConfig Activate changed from %v to %v",
				m.Activate, effectiveActivate)
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
		for i, new := range aiConfig.AppNetAdapterList {
			old := m.AppNetAdapterList[i]
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
			Activate:          effectiveActivate,
			GetStatsIPAddr:    aiConfig.CollectStatsIPAddr,
			CloudInitUserData: aiConfig.CloudInitUserData,
			CipherBlockStatus: aiConfig.CipherBlockStatus,
			MetaDataType:      aiConfig.MetaDataType,
		}
		nc.AppNetAdapterList = make([]types.AppNetAdapterConfig,
			len(aiConfig.AppNetAdapterList))
		for i, ulc := range aiConfig.AppNetAdapterList {
			ul := &nc.AppNetAdapterList[i]
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
		saveCfg := ctx.saveAppNetConfig
		if _, ok := saveCfg[key]; ok {
			config := saveCfg[key]
			log.Tracef("lookupAppNetworkConfig(%s) not found, use saved config", key)
			return &config
		}
		log.Tracef("lookupAppNetworkConfig(%s) not found", key)
		return nil
	}
	config := c.(types.AppNetworkConfig)
	log.Tracef("lookupAppNetworkConfig(%s) found config %+v", key, config) // XXX
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
	config *types.AppNetworkConfig) {

	var akStatus *types.AppKubeNetworkStatus
	sub := ctx.subAppKubeNetStatus
	items := sub.GetAll()
	for _, item := range items {
		status := item.(types.AppKubeNetworkStatus)
		if status.UUIDandVersion.UUID.String() == config.UUIDandVersion.UUID.String() {
			akStatus = &status
			break
		}
	}
	key := config.Key()
	log.Functionf("publishAppNetworkConfig(%s)", key)
	if akStatus != nil {
		pub := ctx.pubAppNetworkConfig
		pub.Publish(key, *config)
	} else {
		ctx.saveAppNetConfig[key] = *config
		log.Functionf("publishAppNetworkConfig(%s), save locally, wait for AppKubeNetStatus", key)
	}
	ctx.anStatusChan <- key
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
	if _, ok := ctx.saveAppNetConfig[key]; ok {
		delete(ctx.saveAppNetConfig, key)
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

	aiStatus.AppNetAdapters = ns.AppNetAdapterList
}
