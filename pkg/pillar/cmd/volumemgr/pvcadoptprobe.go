// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
)

// pvcAdoptProbeTTL throttles repeat "is this PVC ready to adopt" checks
// against the same PVC name. contentTreeSatisfiedByPVCs and
// tryAdoptExistingClusterPVC can both ask about the same PVC on the same
// reconcile pass, and doUpdateVol/doUpdateContentTree can each be re-driven
// many times a second while a download retries -- probe at a bounded rate
// rather than every reconcile.
const pvcAdoptProbeTTL = 15 * time.Second

// pvcAdoptCacheEntry is the last known adoption state of one PVC and when it
// was determined.
type pvcAdoptCacheEntry struct {
	state   kubeapi.PVCAdoptionState
	checked time.Time
}

// pvcAdoptCache is keyed by PVC name, not by ContentTreeStatus.Key() or
// VolumeStatus.Key(). Those two keys can name the same underlying PVC, and
// giving each caller its own throttle timer let one caller's stale
// "not checked yet" outrank the other's fresh answer -- a probe throttled on
// the volume side could report false moments after an unthrottled probe on
// the content-tree side had confirmed the same PVC ready, and doUpdateVol
// read that false as grounds to revoke the acceptance it had just granted.
// Keying by PVC name gives both callers the same answer.
//
// Single-threaded volumemgr main loop, so no lock needed (same pattern as
// clusterStorageReadyCache in retryclustervolume.go).
var pvcAdoptCache = make(map[string]pvcAdoptCacheEntry)

// probePVCAdoption returns the current adoption state of the named PVC, and
// whether reaching that answer required a live Kubernetes call just now
// (false when served from cache within pvcAdoptProbeTTL). A cached state is
// returned as-is, not downgraded to PVCStateUnknown -- the point of the
// cache is to keep serving the last real answer between checks, not to hide
// it until the next unthrottled probe.
//
// Callers that probe several PVCs in one pass use fresh to bound how many
// live, kubeAPITimeout-bounded calls a single reconcile makes -- see
// maxFreshPVCProbesPerCheck in acceptclustercontenttree.go for why that
// bound exists.
func probePVCAdoption(pvcName string) (state kubeapi.PVCAdoptionState, fresh bool) {
	if entry, ok := pvcAdoptCache[pvcName]; ok && time.Since(entry.checked) < pvcAdoptProbeTTL {
		return entry.state, false
	}
	state = kubeapi.ProbePVCAdoption(pvcName, log)
	pvcAdoptCache[pvcName] = pvcAdoptCacheEntry{state: state, checked: time.Now()}
	return state, true
}
