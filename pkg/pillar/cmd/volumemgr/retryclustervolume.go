// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Cache for the EVE-k cluster-storage readiness probe (single-threaded volumemgr
// main loop, so no lock needed). Once ready it stays ready (longhorn/CDI don't
// un-deploy); while not ready we re-probe at most every clusterStorageProbeTTL.
var (
	clusterStorageReadyCache   bool
	clusterStorageReadyCheckAt time.Time
)

const clusterStorageProbeTTL = 15 * time.Second

// maxClusterVolumeRetries bounds how many times a parked volume is re-driven after
// a transient cluster-storage failure. Each retry re-runs RolloutDiskToPVC (which
// can block for minutes), so this caps a misclassified or un-typeable failure at a
// finite number of attempts instead of looping every gc tick forever; once the
// budget is spent the volume is left in a terminal error for the operator to see.
const maxClusterVolumeRetries = 12

// clusterVolumeRetryAction is what retryFailedClusterVolumeCreate should do with a
// single VolumeStatus. Split out as a pure function so the bounded-retry boundary is
// unit-testable without pubsub/worker wiring.
type clusterVolumeRetryAction int

const (
	cvSkip    clusterVolumeRetryAction = iota // not a parked transient cluster-volume failure
	cvRedrive                                 // clear the error and re-drive the create
	cvGiveUp                                  // retry budget spent; leave a terminal error
)

// clusterVolumeRetryActionFor decides, from a VolumeStatus alone, whether the retry
// should skip it, re-drive it, or give up. A volume is a retry candidate only while
// parked in CREATING_VOLUME/PrepareDone with an error kubeapi classified transient;
// once it has been re-driven maxClusterVolumeRetries times it is given up so a
// persistent failure surfaces terminally instead of looping every gc tick.
func clusterVolumeRetryActionFor(status *types.VolumeStatus) clusterVolumeRetryAction {
	if status.State != types.CREATING_VOLUME ||
		status.SubState != types.VolumeSubStatePrepareDone {
		return cvSkip
	}
	if !status.HasError() || !status.ClusterStorageTransientErr {
		return cvSkip
	}
	if status.ClusterStorageRetryCount >= maxClusterVolumeRetries {
		return cvGiveUp
	}
	return cvRedrive
}

// clusterStorageReady reports whether EVE-k longhorn+CDI are ready to create app
// volumes, caching the kube-API probe. The volume-create path calls this so
// volumemgr DEFERS (quietly, no error) until the cluster storage stack is up,
// instead of attempting and failing (storageclass-not-found / no-upload-pod-
// annotation) then relying on the error-retry. Always true off EVE-k.
func clusterStorageReady(ctx *volumemgrContext) bool {
	if !ctx.hvTypeKube {
		return true
	}
	if clusterStorageReadyCache {
		return true
	}
	if time.Since(clusterStorageReadyCheckAt) < clusterStorageProbeTTL {
		return false
	}
	clusterStorageReadyCheckAt = time.Now()
	clusterStorageReadyCache = kubeapi.ClusterStorageReadyForVolumes(log, ctx.nodeName)
	return clusterStorageReadyCache
}

// retryFailedClusterVolumeCreate re-drives volumes parked in a CREATING_VOLUME
// error that kubeapi classified as a transient EVE-k cluster-storage failure
// (longhorn/CDI/k8s-API not ready yet, common right after a kvm->k conversion).
// It clears the error and resubmits the create work; if the create fails again
// the error is set anew, so this self-throttles to at most one retry per gc
// tick. Called from the periodic gc handler.
func retryFailedClusterVolumeCreate(ctx *volumemgrContext) {
	if !ctx.hvTypeKube {
		// PVC/longhorn/CDI volume creation only happens on EVE-k.
		return
	}
	// Until the cluster storage stack is back, a retry would just re-run a
	// RolloutDiskToPVC that blocks for minutes and re-fails, wasting a worker
	// slot; wait for readiness before re-driving.
	if !clusterStorageReady(ctx) {
		return
	}
	for _, st := range ctx.pubVolumeStatus.GetAll() {
		status := st.(types.VolumeStatus)
		switch clusterVolumeRetryActionFor(&status) {
		case cvSkip:
			continue
		case cvGiveUp:
			// Leave the volume parked in its error; clearing the transient verdict
			// makes it no longer eligible here, so a persistent failure surfaces to
			// the operator instead of looping forever.
			log.Errorf("retryFailedClusterVolumeCreate: giving up on volume %s (%s) "+
				"after %d retries; leaving terminal error: %s",
				status.Key(), status.DisplayName, status.ClusterStorageRetryCount, status.Error)
			status.ClusterStorageTransientErr = false
			publishVolumeStatus(ctx, &status)
		case cvRedrive:
			status.ClusterStorageRetryCount++
			log.Noticef("retryFailedClusterVolumeCreate: retrying volume %s (%s) "+
				"(attempt %d/%d) after transient cluster-storage error: %s",
				status.Key(), status.DisplayName, status.ClusterStorageRetryCount,
				maxClusterVolumeRetries, status.Error)
			status.ClearErrorWithSource()
			publishVolumeStatus(ctx, &status)
			AddWorkCreate(ctx, &status)
		}
	}
}
