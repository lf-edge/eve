// Copyright (c) 2024-2025 Zededa, Inc.
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
			handleCreateAppInstanceStatus(ctx, *aiConfig)
		} else {
			// Kubernetes placing the pod here does not mean this node's own
			// copy of the volume is ready: the app-start lease lets a
			// different node create the object before this node's own
			// upload finishes, and Kubernetes schedules the pod as soon as
			// the object exists. updateAIStatusUUID runs the normal
			// doUpdate path, which only activates once this node's
			// VolumeRefStatus reaches CREATED_VOLUME; activating here
			// unconditionally let a VM start against a volume its own CDI
			// upload was still writing, and Longhorn rejected the upload
			// pod's mount because the VM already held the volume.
			updateAIStatusUUID(ctx, key)
			log.Functionf("handleENClusterAppStatusImpl(%s) for app-status %v aiStatus %v", key, status, aiStatus)
			return
		}
	} else { // not scheduled here.

		// if aiStatus is not present, nothing to do
		if aiStatus != nil {
			// If I am not scheduled here, modify and publish the aiStatus with NoUploadStatsToController set.
			publishAppInstanceStatus(ctx, aiStatus)
			publishAppInstanceSummary(ctx)
		}

	}

}

func handleKubeLeaderElectInfoCreate(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	info := configArg.(types.KubeLeaderElectInfo)
	handleKubeLeaderElectInfoImpl(ctx, key, &info)
}

func handleKubeLeaderElectInfoModify(ctxArg interface{}, key string, configArg interface{}, oldConfigArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	info := configArg.(types.KubeLeaderElectInfo)
	handleKubeLeaderElectInfoImpl(ctx, key, &info)
}

func handleKubeLeaderElectInfoDelete(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	// Loss of the publication is treated the same as loss of the lease.
	info := types.KubeLeaderElectInfo{}
	handleKubeLeaderElectInfoImpl(ctx, key, &info)
}

// handleKubeLeaderElectInfoImpl tracks whether this node holds the app-start
// lease. getKubeAppActivateStatus lets the holder submit the app start, so a
// change of holder can release apps that no other node was able to start.
func handleKubeLeaderElectInfoImpl(ctx *zedmanagerContext, key string,
	info *types.KubeLeaderElectInfo) {

	if ctx.isAppStartLeader == info.IsAppStartLeader {
		return
	}
	log.Noticef("handleKubeLeaderElectInfoImpl(%s): app-start leader %t -> %t",
		key, ctx.isAppStartLeader, info.IsAppStartLeader)
	ctx.isAppStartLeader = info.IsAppStartLeader
	updateAllAppInstances(ctx)
}

// updateAllAppInstances re-drives every app instance. It is for a change that
// can alter the effective activate state of all of them at once, rather than
// of one named app.
func updateAllAppInstances(ctx *zedmanagerContext) {
	items := ctx.subAppInstanceConfig.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		if localConfig := lookupLocalAppInstanceConfig(ctx, config.Key()); localConfig != nil {
			config = *localConfig
		}
		status := lookupAppInstanceStatus(ctx, config.Key())
		if status == nil {
			continue
		}
		if doUpdate(ctx, config, status) {
			publishAppInstanceStatus(ctx, status)
		}
	}
}
