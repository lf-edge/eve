// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// backupDNIDFunc matches kubeapi.IsCurrentlyBackupDNID. Held on the context,
// mirroring zedmanager's own backupDNIDFunc (cmd/zedmanager/dnidbackup.go),
// so the gate can be decided in a test without a cluster.
type backupDNIDFunc func(log *base.LogObject, designatedNodeID string,
	isAppOpLeader bool, affinity types.Affinity, threshold time.Duration) bool

// dnidOutageThreshold is how long a volume's designated node must have been
// unhealthy before a peer may act on it. Mirrors zedmanager's own function of
// the same name (cmd/zedmanager/dnidbackup.go).
func dnidOutageThreshold(ctx *volumemgrContext) time.Duration {
	if ctx.globalConfig == nil {
		return 0
	}
	seconds := ctx.globalConfig.GlobalValueInt(types.DnidOutageThresholdForUsage)
	return time.Duration(seconds) * time.Second
}

// isCurrentlyBackupDNIDForVolume reports whether this node may act on a
// replicated volume in its designated node's place. Mirrors zedmanager's
// isCurrentlyBackupDNIDForApp: everything cheap is checked before the one
// live API call, so a node that does not hold the lease, or a volume with no
// designated node, costs nothing.
func isCurrentlyBackupDNIDForVolume(ctx *volumemgrContext, config *types.VolumeConfig) bool {
	if config == nil || !ctx.hvTypeKube || !ctx.isAppOpLeader {
		return false
	}
	if config.DesignatedNodeUUID == "" {
		return false
	}
	return ctx.isCurrentlyBackupDNIDFunc(log, config.DesignatedNodeUUID,
		ctx.isAppOpLeader, config.AffinityType, dnidOutageThreshold(ctx))
}

// reevaluateBackupDNIDVolumes re-drives a replicated volume's doUpdateVol
// once its designated node has newly become eligible for backup-DNID
// takeover. Backup DNID changes nothing in the volume's own config (the
// controller has no idea a peer is standing in), so nothing else re-drives
// doUpdateVol for this case -- no Modify event ever arrives for it. Resets
// State/SubState back to INITIAL first: doUpdateVol's own "already
// CREATED_VOLUME" exit would otherwise immediately re-block the very call
// meant to unblock it.
func reevaluateBackupDNIDVolumes(ctx *volumemgrContext) {
	for _, s := range ctx.pubVolumeStatus.GetAll() {
		status := s.(types.VolumeStatus)
		if !status.IsReplicated || status.State != types.CREATED_VOLUME {
			continue
		}
		config := ctx.LookupVolumeConfig(status.Key())
		if config == nil || !isCurrentlyBackupDNIDForVolume(ctx, config) {
			continue
		}
		log.Noticef("reevaluateBackupDNIDVolumes(%s): designated node %s now eligible for backup takeover, re-driving",
			status.Key(), config.DesignatedNodeUUID)
		status.State = types.INITIAL
		status.SubState = types.VolumeSubStateInitial
		changed, _ := doUpdateVol(ctx, &status)
		if changed {
			publishVolumeStatus(ctx, &status)
			updateVolumeRefStatus(ctx, &status)
			if err := createOrUpdateAppDiskMetrics(ctx, agentName, &status); err != nil {
				log.Errorf("reevaluateBackupDNIDVolumes(%s): exception while publishing diskmetric. %s",
					status.Key(), err.Error())
			}
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
	ctx := ctxArg.(*volumemgrContext)
	info := statusArg.(types.KubeLeaderElectInfo)
	if ctx.isAppOpLeader == info.IsAppOpLeader {
		return
	}
	log.Noticef("handleKubeLeaderElectInfo(%s): app-op leader %v -> %v (holder %q)",
		key, ctx.isAppOpLeader, info.IsAppOpLeader, info.AppOpLeaderIdentity)
	ctx.isAppOpLeader = info.IsAppOpLeader
	// Gaining the lease can make pending work actionable at once, so do not
	// wait for the next gc tick to notice.
	if ctx.isAppOpLeader {
		reevaluateBackupDNIDVolumes(ctx)
	}
}

func handleKubeLeaderElectInfoDelete(ctxArg interface{}, key string,
	_ interface{}) {
	ctx := ctxArg.(*volumemgrContext)
	if !ctx.isAppOpLeader {
		return
	}
	log.Noticef("handleKubeLeaderElectInfoDelete(%s): app-op leadership dropped", key)
	ctx.isAppOpLeader = false
}
