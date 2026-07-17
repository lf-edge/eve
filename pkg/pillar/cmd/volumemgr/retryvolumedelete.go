// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// maxVolumeDeleteRetries bounds how many times a volume whose destroy failed is
// re-driven off the gc tick before volumemgr gives up. Deleting a PVC/Longhorn
// volume is normally quick, but the owner node can be unreachable for a while
// during a purge or a cluster update; this budget covers such a window (~gc
// interval * this count) while still parking a permanently-undeletable volume
// terminally instead of resubmitting a worker job forever.
const maxVolumeDeleteRetries = 12

// volumeDeleteRetryAction is what retryFailedVolumeDelete should do with a single
// VolumeStatus. Split out as a pure function so the bounded-retry boundary is
// unit-testable without pubsub/worker wiring.
type volumeDeleteRetryAction int

const (
	vdSkip    volumeDeleteRetryAction = iota // not a parked failed delete
	vdRedrive                                // resubmit the destroy work
	vdGiveUp                                 // retry budget just spent; log once and park terminally
	vdParked                                 // already given up; leave published, do nothing
)

// volumeDeleteRetryActionFor decides, from a VolumeStatus and how many times its
// delete has already been re-driven, whether to skip it, re-drive it, give up, or
// leave it parked. A volume is a retry candidate only while it is unreferenced
// (RefCount 0), parked in the Deleting sub-state, and carries an error - i.e. a
// destroy that failed rather than one still in flight. It is re-driven until it has
// been retried maxVolumeDeleteRetries times, at which point it is given up once and
// then left parked (still published with its error, for operator visibility) so a
// permanently-failing delete stops consuming worker slots without disappearing.
func volumeDeleteRetryActionFor(status *types.VolumeStatus, retryCount int) volumeDeleteRetryAction {
	if status.RefCount != 0 ||
		status.SubState != types.VolumeSubStateDeleting ||
		!status.HasError() {
		return vdSkip
	}
	if retryCount > maxVolumeDeleteRetries {
		return vdParked
	}
	if retryCount == maxVolumeDeleteRetries {
		return vdGiveUp
	}
	return vdRedrive
}

// retryFailedVolumeDelete re-drives volume deletions that previously failed and
// were left published (by maybeDeleteVolume) in the Deleting sub-state with an
// error, rather than being unpublished and leaked. For each such volume it
// resubmits the destroy work; the result flows back through
// processVolumeWorkResult -> maybeDeleteVolume, which unpublishes on success
// (clearing the retry count) or leaves the error set for another pass. After
// maxVolumeDeleteRetries attempts it gives up: the volume is left published in the
// Deleting sub-state with its error (mirroring the cluster-create give-up) so a
// permanently-undeletable, possibly-orphaned volume stays visible to the operator
// in status instead of silently disappearing; it just stops being re-driven.
// Called from the periodic gc handler.
func retryFailedVolumeDelete(ctx *volumemgrContext) {
	for _, st := range ctx.pubVolumeStatus.GetAll() {
		status := st.(types.VolumeStatus)
		key := status.Key()
		switch volumeDeleteRetryActionFor(&status, ctx.volumeDeleteRetryCount[key]) {
		case vdSkip:
			// Not (or no longer) a parked failed delete. Drop any stale retry
			// count so a volume that left the candidate set another way (e.g. it
			// got re-referenced during a redeploy) doesn't resume a later delete
			// from a shortened budget. A no-op for untracked keys.
			delete(ctx.volumeDeleteRetryCount, key)
			continue
		case vdParked:
			// Already gave up on this delete; it stays published with its error
			// for operator visibility. Nothing more to do until it stops being a
			// candidate (handled by vdSkip above).
			continue
		case vdGiveUp:
			log.Errorf("retryFailedVolumeDelete: giving up on delete of %s (%s) "+
				"after %d retries; leaving it published in Deleting with a terminal "+
				"error, underlying volume may be orphaned: %s",
				key, status.DisplayName, ctx.volumeDeleteRetryCount[key], status.Error)
			// Consume the stale worker result but keep the VolumeStatus (and its
			// disk metrics) published; bump the count past the cap so subsequent gc
			// ticks see vdParked and neither re-drive nor re-log.
			_ = popVolumeWorkResult(ctx, key)
			ctx.volumeDeleteRetryCount[key] = maxVolumeDeleteRetries + 1
		case vdRedrive:
			ctx.volumeDeleteRetryCount[key]++
			log.Noticef("retryFailedVolumeDelete: retrying delete of %s (%s) "+
				"(attempt %d/%d): %s",
				key, status.DisplayName, ctx.volumeDeleteRetryCount[key],
				maxVolumeDeleteRetries, status.Error)
			AddWorkDestroy(ctx, &status)
		}
	}
}
