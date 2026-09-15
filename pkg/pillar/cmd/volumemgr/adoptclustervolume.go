// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// tryAdoptExistingClusterPVC is the EVE-k/Longhorn cluster-failover fast path.
//
// Background: on a DNID reassignment (an app re-designated to a healthy node
// after the original node became unavailable), the new node's VolumeConfig
// flips IsReplicated false->true->false as ownership moves (see
// handleVolumeModify), but the ContentTree backing this volume may be missing
// entirely on the new node, or fighting a slow/unreachable datastore -- while
// the Longhorn PVC for this exact volume generation is already Bound and fully
// populated cluster-wide via replication. There is no reason to make the app
// wait on re-establishing that source image: hand off straight to
// CreateVolume(), whose existing FindPVC/upload-complete check (csihandler.go)
// adopts the PVC in place instead of re-driving a download/import.
//
// Guarded to EVE-k only: classic hypervisors have no PVC/Longhorn concept, so
// ctx.hvTypeKube false always short-circuits to false here, leaving that path
// completely unchanged. On EVE-k, every persistent volume is CSI/Longhorn
// backed, so that one guard is sufficient scoping -- no separate "is this a
// Longhorn PVC" check is needed.
//
// This does not weaken the existing safety checks, it only adds a second way
// to reach them sooner:
//   - Generation matching is implicit: VolumeStatus.GetPVCName() embeds the
//     generation counter in the PVC name itself, so this can only ever match
//     the PVC for the exact generation being requested.
//   - Completeness is still required: kubeapi.ProbePVCAdoption checks the PVC
//     is Bound and CDI's own "Upload Complete" annotations are present, the
//     same signal the existing (already-present) adopt-on-create logic in
//     csihandler.go relies on.
//
// Returns the PVC's adoption state (see kubeapi.PVCAdoptionState). Callers
// must only treat PVCStateAbsent as evidence this volume needs a real
// download -- PVCStateUnknown and PVCStateNotReady both mean the volume
// keeps waiting on the ContentTree exactly as it does today, not that it
// should start over.
func tryAdoptExistingClusterPVC(ctx *volumemgrContext, status *types.VolumeStatus) kubeapi.PVCAdoptionState {
	if !ctx.hvTypeKube {
		return kubeapi.PVCStateUnknown
	}
	key := status.Key()
	pvcName := status.GetPVCName()
	// This function makes at most one probe, so the live-call budget
	// probePVCAdoption's second return value guards (see
	// maxFreshPVCProbesPerCheck) does not apply here; reevaluatePendingVolumes
	// already re-drives doUpdateVol every gc tick regardless.
	state, _ := probePVCAdoption(pvcName)
	switch state {
	case kubeapi.PVCStateReady:
		log.Noticef("tryAdoptExistingClusterPVC(%s): found existing Bound, upload-complete PVC %s "+
			"at this volume's generation; adopting instead of waiting on ContentTree %s",
			key, pvcName, status.ContentID)
	case kubeapi.PVCStateAbsent:
		log.Functionf("tryAdoptExistingClusterPVC(%s): PVC %s confirmed absent", key, pvcName)
	default:
		log.Functionf("tryAdoptExistingClusterPVC(%s): PVC %s not yet known ready", key, pvcName)
	}
	return state
}
