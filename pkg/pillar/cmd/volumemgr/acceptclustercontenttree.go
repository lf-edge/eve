// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// maxFreshPVCProbesPerCheck bounds live PVC checks per call: each is a
// kubeAPITimeout-bounded Kubernetes call, and enough of them chained in one
// doUpdateContentTree call, with no watchdog touch in between, could starve
// volumemgr's watchdog budget. reevaluatePendingContentTrees picks up
// whatever a capped call defers.
const maxFreshPVCProbesPerCheck = 2

// contentTreeSatisfiedByPVCs reports whether every volume this node is
// responsible for that references this content tree already has a Bound,
// upload-complete Longhorn PVC at its requested generation.
//
// Background: EVE only has two ways to reach LOADED -- download the source,
// or learn this node isn't the designated one (IsLocal false, parked at
// LOADED with no blobs). Neither covers the case after a cluster event,
// where the source isn't here but the PVC it exists to fill already is --
// so without this check the node re-downloads a multi-GB image nothing will
// ever read again, since CDI already populated the PVC and KubeVirt attaches
// it directly.
//
// Conservative by construction:
//   - EVE-k only; classic hypervisors have no PVC to be satisfied by.
//   - Volumes owned by another node (IsReplicated) are skipped: this node is
//     not the one that would download for them.
//   - Requires at least one referencing volume. A content tree with no volume
//     yet has nothing to judge by, so it downloads exactly as it does today.
//   - Requires *every* referencing volume to be satisfied. One volume at a new
//     generation (a purge) has a different PVC name, will not be found, and so
//     holds the whole tree on the normal download path.
//   - Any API error is "not satisfied": callers keep the existing behaviour.
func contentTreeSatisfiedByPVCs(ctx *volumemgrContext, status *types.ContentTreeStatus) bool {
	if !ctx.hvTypeKube {
		return false
	}
	key := status.Key()

	refs := 0
	freshProbes := 0
	for _, c := range ctx.subVolumeConfig.GetAll() {
		vc := c.(types.VolumeConfig)
		if vc.ContentID != status.ContentID {
			continue
		}
		if vc.IsReplicated {
			// Another node is the designated owner; it downloads, not us.
			continue
		}
		if freshProbes >= maxFreshPVCProbesPerCheck {
			// Live-probe budget spent this call. Whatever volumes remain
			// unchecked stay that way until reevaluatePendingContentTrees
			// drives this content tree again, rather than chaining more
			// blocking calls into this one reconcile pass.
			log.Functionf("contentTreeSatisfiedByPVCs(%s): live-probe budget spent, deferring the rest",
				key)
			return false
		}
		refs++
		pvcName := vc.GetPVCName()
		state, fresh := probePVCAdoption(pvcName)
		if fresh {
			freshProbes++
		}
		if state != kubeapi.PVCStateReady {
			log.Functionf("contentTreeSatisfiedByPVCs(%s): PVC %s not yet ready for adoption",
				key, pvcName)
			return false
		}
	}
	if refs == 0 {
		log.Functionf("contentTreeSatisfiedByPVCs(%s): no local volumes reference this content tree", key)
		return false
	}
	log.Noticef("contentTreeSatisfiedByPVCs(%s) name %s: all %d referencing volume(s) already have "+
		"complete PVCs; the source image is not needed on this node",
		key, status.DisplayName, refs)
	return true
}

// reevaluatePendingContentTrees re-drives every ContentTreeStatus still below
// VERIFIED, so a check maxFreshPVCProbesPerCheck deferred gets finished on a
// later pass -- the same role reevaluatePendingVolumes plays for volumes.
// Called from the periodic gc handler.
func reevaluatePendingContentTrees(ctx *volumemgrContext) {
	if !ctx.hvTypeKube {
		// The accept-from-PVCs path this re-drives is EVE-k only.
		return
	}
	for _, s := range ctx.pubContentTreeStatus.GetAll() {
		status := s.(types.ContentTreeStatus)
		if status.State >= types.VERIFIED {
			continue
		}
		changed, _ := doUpdateContentTree(ctx, &status)
		if changed {
			publishContentTreeStatus(ctx, &status)
		}
	}
}

// acceptContentTreeFromPVCs marks a content tree satisfied without
// downloading it. REMOTELOADED maps back to LOADED at the API layer, so the
// controller still shows the content online; no BlobStatus or
// DownloaderConfig gets published, so no download starts.
func acceptContentTreeFromPVCs(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	log.Noticef("acceptContentTreeFromPVCs(%s) name %s: accepting content tree from existing "+
		"cluster PVCs, skipping download of %s",
		status.Key(), status.DisplayName, status.RelativeURL)
	status.State = types.REMOTELOADED
	status.ClearErrorWithSource()
}

// revokeContentTreeAcceptance undoes an acceptance a volume's own state
// disproved (a new generation after a purge, or a PVC that's since gone): it
// deletes and recreates the tree the same way handleContentTreeModify does
// when a node becomes newly responsible, re-entering the download pipeline
// from INITIAL.
//
// Does not call updateContentTree: the only caller is already inside
// doUpdateVol for the volume that triggered this, and updateContentTree
// would just fan back out to it via updateVolumeStatusFromContentID. The
// recreated tree publishes its own status; downloader/verifier drive it
// forward from there like any other download.
func revokeContentTreeAcceptance(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	key := status.Key()
	config := lookupContentTreeConfig(ctx, key)
	if config == nil {
		log.Warnf("revokeContentTreeAcceptance(%s): no ContentTreeConfig, cannot re-drive download", key)
		return
	}
	log.Noticef("revokeContentTreeAcceptance(%s) name %s: a referencing volume needs content no PVC "+
		"provides; re-entering the download pipeline", key, status.DisplayName)
	deleteContentTree(ctx, status, 0) // immediate; nothing was downloaded to keep
	newStatus := createContentTreeStatus(ctx, *config)
	if changed, _ := doUpdateContentTree(ctx, newStatus); changed {
		publishContentTreeStatus(ctx, newStatus)
	}
}

// contentTreeNotLocallyUsable reports whether a volume cannot be created from
// this content tree's local content right now: it is missing, still working
// its way through download/verify, or was accepted from existing PVCs and so
// has no local content at all. In every one of those cases a volume whose PVC
// already exists should adopt it rather than wait.
func contentTreeNotLocallyUsable(ctStatus *types.ContentTreeStatus) bool {
	if ctStatus == nil {
		return true
	}
	return ctStatus.State < types.LOADED || ctStatus.State == types.REMOTELOADED
}
