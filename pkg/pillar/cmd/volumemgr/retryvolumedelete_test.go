// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// parkedFailedDeleteVolume builds a VolumeStatus in the state the volume-delete
// retry treats as a candidate: unreferenced, in the Deleting sub-state, with a
// recorded error (a destroy that failed rather than one still in flight).
func parkedFailedDeleteVolume() types.VolumeStatus {
	vs := types.VolumeStatus{
		RefCount: 0,
		SubState: types.VolumeSubStateDeleting,
	}
	vs.SetErrorDescription(types.ErrorDescription{Error: "DeletePVC failed: node unreachable"})
	return vs
}

// TestVolumeDeleteRetryActionFor pins the bounded-retry boundary: a parked failed
// delete is re-driven until it has been retried maxVolumeDeleteRetries times, at
// which point the retry gives up exactly once and then leaves the volume parked
// (still published with its error) instead of resubmitting a destroy worker job or
// re-logging every gc tick forever. Anything that is not a parked failed delete is
// skipped.
func TestVolumeDeleteRetryActionFor(t *testing.T) {
	// Under the cap: re-drive.
	for _, n := range []int{0, 1, maxVolumeDeleteRetries - 1} {
		vs := parkedFailedDeleteVolume()
		if got := volumeDeleteRetryActionFor(&vs, n); got != vdRedrive {
			t.Errorf("retryCount=%d: got %d, want vdRedrive(%d)", n, got, vdRedrive)
		}
	}
	// Exactly at the cap: give up (log once, park).
	{
		vs := parkedFailedDeleteVolume()
		if got := volumeDeleteRetryActionFor(&vs, maxVolumeDeleteRetries); got != vdGiveUp {
			t.Errorf("retryCount=%d: got %d, want vdGiveUp(%d)",
				maxVolumeDeleteRetries, got, vdGiveUp)
		}
	}
	// Beyond the cap: already given up, stay parked (no re-drive, no re-log).
	for _, n := range []int{maxVolumeDeleteRetries + 1, maxVolumeDeleteRetries + 5} {
		vs := parkedFailedDeleteVolume()
		if got := volumeDeleteRetryActionFor(&vs, n); got != vdParked {
			t.Errorf("retryCount=%d: got %d, want vdParked(%d)", n, got, vdParked)
		}
	}
	// Not a retry candidate: skip.
	skips := map[string]func(*types.VolumeStatus){
		"still referenced": func(v *types.VolumeStatus) { v.RefCount = 1 },
		"not deleting":     func(v *types.VolumeStatus) { v.SubState = types.VolumeSubStateCreated },
	}
	for name, mutate := range skips {
		vs := parkedFailedDeleteVolume()
		mutate(&vs)
		if got := volumeDeleteRetryActionFor(&vs, 0); got != vdSkip {
			t.Errorf("%s: got %d, want vdSkip(%d)", name, got, vdSkip)
		}
	}

	// A fresh (never-failed) delete in flight must not be treated as a failed
	// delete: Deleting sub-state but no error yet.
	inFlight := types.VolumeStatus{SubState: types.VolumeSubStateDeleting}
	if got := volumeDeleteRetryActionFor(&inFlight, 0); got != vdSkip {
		t.Errorf("in-flight delete: got %d, want vdSkip(%d)", got, vdSkip)
	}
}
