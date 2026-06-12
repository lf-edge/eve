// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"bytes"
	"reflect"
	"slices"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MaybeAddAppNetworkConfig ensures we have an AppNetworkConfig
//
// A change to the application's network adapters (their number, their order,
// or any field of an existing adapter other than ACLs) reconfigures the
// network stack (bridge, dnsmasq, VIFs). While the application is running such
// a change is withheld from
// zedrouter (stageNetwork below) so the network is not reconfigured underneath
// the running guest; it is published instead on the next restart (or when the
// app is being started), so zedrouter reconfigures the network as part of the
// (re)start. ACL and other field changes are applied live.
func MaybeAddAppNetworkConfig(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig, aiStatus *types.AppInstanceStatus) {

	key := aiConfig.Key()
	displayName := aiConfig.DisplayName
	log.Functionf("MaybeAddAppNetworkConfig for %s displayName %s", key,
		displayName)

	effectiveActivate := effectiveActivateCombined(aiConfig, ctx)

	changed := false
	stageNetwork := false
	m := lookupAppNetworkConfig(ctx, key)
	if m != nil {
		log.Functionf("appNetwork config already exists for %s", key)
		if !reflect.DeepEqual(m.AppNetAdapterList, aiConfig.AppNetAdapterList) {
			log.Functionf("MaybeAddAppNetworkConfig: AppNetAdapters changed "+
				"from %+v to %+v for %s", m.AppNetAdapterList,
				aiConfig.AppNetAdapterList, aiConfig.UUIDandVersion)
			changed = true
			if adapterChangeNeedsRestart(m.AppNetAdapterList,
				aiConfig.AppNetAdapterList) {
				stageNetwork = true
			}
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
	} else {
		log.Tracef("appNetwork config add for %s", key)
		changed = true
	}
	if !changed {
		log.Functionf("MaybeAddAppNetworkConfig done (no change) for %s", key)
		return
	}
	// Stage network-reconfiguring changes while the guest is running; they are
	// applied on the next restart (when RestartInprogress is set). If the app is
	// not currently activated it is being started, so there is no running guest
	// to protect and the change is applied immediately.
	if stageNetwork && aiStatus.Activated &&
		aiStatus.RestartInprogress == types.NotInprogress {
		log.Noticef("MaybeAddAppNetworkConfig(%s): network adapter change staged; "+
			"will be applied when the application is restarted", key)
		return
	}
	nc := types.AppNetworkConfig{
		UUIDandVersion:    aiConfig.UUIDandVersion,
		DisplayName:       aiConfig.DisplayName,
		Activate:          effectiveActivate,
		GetStatsIPAddr:    aiConfig.CollectStatsIPAddr,
		CloudInitUserData: aiConfig.CloudInitUserData,
		CipherBlockStatus: aiConfig.CipherBlockStatus,
		MetaDataType:      aiConfig.MetaDataType,
		DeploymentType:    aiConfig.DeploymentType, // can not be dynamically changed
	}
	nc.AppNetAdapterList = slices.Clone(aiConfig.AppNetAdapterList)
	publishAppNetworkConfig(ctx, &nc)
	log.Functionf("MaybeAddAppNetworkConfig done for %s", key)
}

// adapterChangeNeedsRestart reports whether the difference between the old and
// the new adapter list cannot be applied to a running application. Only ACL
// changes are applied live by zedrouter; any other difference (the number of
// adapters, or an adapter's name, network, IP, MAC, interface order, VLAN, ...)
// reconfigures the network stack and therefore has to wait until the
// application is restarted. Note that the adapter lists are sorted by
// IntfOrder (see zedagent's parseAppNetAdapterConfig), so a pure reordering
// also shows up as a difference here, as it must: it changes the order in
// which the guest enumerates its NICs.
func adapterChangeNeedsRestart(oldList, newList []types.AppNetAdapterConfig) bool {
	withoutACLs := func(adapters []types.AppNetAdapterConfig) []types.AppNetAdapterConfig {
		stripped := make([]types.AppNetAdapterConfig, len(adapters))
		copy(stripped, adapters)
		for i := range stripped {
			stripped[i].ACLs = nil
		}
		return stripped
	}
	return !reflect.DeepEqual(withoutACLs(oldList), withoutACLs(newList))
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

	aiStatus.AppNetAdapters = ns.AppNetAdapterList
}
