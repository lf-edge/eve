// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import "github.com/lf-edge/eve/pkg/pillar/types"

func handleENClusterAppStatusCreate(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleENClusterAppStatusCreate(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusModify(ctxArg interface{}, key string, configArg interface{}, oldConfigArg interface{}) {
	log.Noticef("handleENClusterAppStatusModify(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusDelete(ctxArg interface{}, key string, configArg interface{}) {
	log.Noticef("handleENClusterAppStatusDelete(%s)", key)
	ctx := ctxArg.(*zedmanagerContext)
	status := configArg.(types.ENClusterAppStatus)
	handleENClusterAppStatusImpl(ctx, key, &status)
}

func handleENClusterAppStatusImpl(ctx *zedmanagerContext, key string, status *types.ENClusterAppStatus) {

	aiStatus := lookupAppInstanceStatus(ctx, key)
	log.Noticef("handleENClusterAppStatusImpl(%s) for app-status %v aiStatus %v", key, status, aiStatus)

	if status.ScheduledOnThisNode {
		if aiStatus == nil {
			// This could happen if app failover to other node and failing back to this designated node.
			// One scenario is node reboot. Kubernetes told us that app is scheduled on this node.
			aiConfig := lookupAppInstanceConfig(ctx, key, false)
			if aiConfig == nil {
				log.Errorf("handleENClusterAppStatusImpl(%s) AppInstanceConfig missing for app", key)
				return
			}
			// XXX this will be handled in later PR in clustering and zedmanager code
			//handleCreateAppInstanceStatus(ctx, *aiConfig)
		} else {
			// Nothing to do, we already have aiStatus
			log.Functionf("handleENClusterAppStatusImpl(%s) for app-status %v aiStatus %v", key, status, aiStatus)
			return
		}
	} else { // not scheduled here.

		// if aiStatus is not present, nothing to do
		if aiStatus != nil {
			// If I am not scheduled here, just unpublish the AIStatus.
			// We probably had app running on this node earlier before failover.
			unpublishAppInstanceStatus(ctx, aiStatus)
		}

	}
}
