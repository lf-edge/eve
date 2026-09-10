// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// backupDNIDFunc matches kubeapi.IsCurrentlyBackupDNID. Held on the context so
// the gate can be decided in a test without a cluster.
type backupDNIDFunc func(log *base.LogObject, designatedNodeID string,
	isAppOpLeader bool, affinity types.Affinity, threshold time.Duration) bool

// lookupENClusterAppStatus returns this node's cluster view of one app, or nil
// if zedkube has published none yet. Keyed rather than scanned: zedkube
// publishes under aiconfig.Key(), which is the app UUID.
func lookupENClusterAppStatus(ctx *zedmanagerContext,
	key string) *types.ENClusterAppStatus {
	item, err := ctx.subENClusterAppStatus.Get(key)
	if err != nil {
		return nil
	}
	status, ok := item.(types.ENClusterAppStatus)
	if !ok {
		return nil
	}
	return &status
}

// placedHere reports whether Kubernetes has this app on this node, either
// because this node owns it or because the pod was scheduled here.
func placedHere(status *types.ENClusterAppStatus) bool {
	if status == nil {
		return false
	}
	return status.IsDNidNode || status.ScheduledOnThisNode
}

// onTheDeviceForApp reports whether this node should run the app's domain:
// Kubernetes already has it here, or this node stands in for a downed
// designated node.
//
// isBackupDNID is a function so the costly live health read is skipped
// whenever placement alone decides. A nil status -- never placed anywhere
// -- means only a backup node may act.
//
// ScheduledOnThisNode is kept as a term to stop failback thrash: it stays
// true until Kubernetes actually moves the pod off this node.
func onTheDeviceForApp(status *types.ENClusterAppStatus,
	isBackupDNID func() bool) bool {
	if placedHere(status) {
		return true
	}
	return isBackupDNID()
}

// dnidOutageThreshold is how long an app's designated node must have been
// unhealthy before a peer may act for it.
func dnidOutageThreshold(ctx *zedmanagerContext) time.Duration {
	if ctx.globalConfig == nil {
		return 0
	}
	seconds := ctx.globalConfig.GlobalValueInt(types.DnidOutageThresholdForUsage)
	return time.Duration(seconds) * time.Second
}

// isCurrentlyBackupDNIDForApp reports whether this node may act for aiConfig's
// designated node. Everything cheap is checked here so that a node which does
// not hold the lease, or an app with no designated node, costs no API call.
func isCurrentlyBackupDNIDForApp(ctx *zedmanagerContext,
	aiConfig types.AppInstanceConfig) bool {
	if !ctx.hvTypeKube || !ctx.isAppOpLeader {
		return false
	}
	if aiConfig.DesignatedNodeUUID == "" || aiConfig.IsDesignatedNodeID {
		return false
	}
	return ctx.isCurrentlyBackupDNIDFunc(log, aiConfig.DesignatedNodeUUID,
		ctx.isAppOpLeader, aiConfig.AffinityType, dnidOutageThreshold(ctx))
}

// backupCandidates are the cluster apps whose desired state a backup decision
// could still change: this node is not their designated node, they can fail
// over at all, and they are not already running here. Pure state, no API
// calls, so asking is cheap enough to do on every pass.
func backupCandidates(ctx *zedmanagerContext) []types.AppInstanceConfig {
	var candidates []types.AppInstanceConfig
	for _, c := range ctx.subAppInstanceConfig.GetAll() {
		config := c.(types.AppInstanceConfig)
		// A snapshot rollback replaces the config; honor it, as
		// updateBasedOnProfile does.
		if localConfig := lookupLocalAppInstanceConfig(ctx, config.Key()); localConfig != nil {
			config = *localConfig
		}
		if config.IsDesignatedNodeID || config.DesignatedNodeUUID == "" {
			continue
		}
		if config.AffinityType == types.RequiredDuringScheduling {
			// Kubernetes would refuse to place it here regardless.
			continue
		}
		if placedHere(lookupENClusterAppStatus(ctx, config.Key())) {
			continue
		}
		candidates = append(candidates, config)
	}
	return candidates
}

// reevaluateAppInstances re-drives every app a backup decision could change.
// Level-triggered on purpose: it re-drives whenever the desired state is not
// met rather than on an edge, because an edge is consumed even when the
// resulting doUpdate cannot finish the job -- volume not ready, memory
// pressure, another status pending -- and would then never fire again.
func reevaluateAppInstances(ctx *zedmanagerContext) {
	candidates := backupCandidates(ctx)
	if len(candidates) == 0 {
		return
	}
	log.Functionf("reevaluateAppInstances: %d candidate(s)", len(candidates))
	for _, config := range candidates {
		status := lookupAppInstanceStatus(ctx, config.Key())
		if status == nil {
			continue
		}
		if doUpdate(ctx, config, status) {
			publishAppInstanceStatus(ctx, status)
		}
	}
}

func handleKubeLeaderElectInfoCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleKubeLeaderElectInfoImpl(ctxArg, key, statusArg)
}

func handleKubeLeaderElectInfoModify(ctxArg interface{}, key string,
	statusArg interface{}, _ interface{}) {
	handleKubeLeaderElectInfoImpl(ctxArg, key, statusArg)
}

func handleKubeLeaderElectInfoImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	info := statusArg.(types.KubeLeaderElectInfo)
	if ctx.isAppOpLeader == info.IsAppOpLeader {
		return
	}
	log.Noticef("handleKubeLeaderElectInfo(%s): app-op leader %v -> %v (holder %q)",
		key, ctx.isAppOpLeader, info.IsAppOpLeader, info.AppOpLeaderIdentity)
	ctx.isAppOpLeader = info.IsAppOpLeader
	// Gaining the lease can make pending work actionable at once, so do not
	// wait for the next tick to notice.
	if ctx.isAppOpLeader {
		reevaluateAppInstances(ctx)
	}
}

func handleKubeLeaderElectInfoDelete(ctxArg interface{}, key string,
	_ interface{}) {
	ctx := ctxArg.(*zedmanagerContext)
	if !ctx.isAppOpLeader {
		return
	}
	log.Noticef("handleKubeLeaderElectInfoDelete(%s): app-op leadership dropped", key)
	ctx.isAppOpLeader = false
}
