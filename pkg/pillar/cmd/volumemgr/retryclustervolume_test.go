// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// parkedTransientVolume builds a VolumeStatus in the state the cluster-volume retry
// treats as a candidate: CREATING_VOLUME/PrepareDone, a recorded error, and a
// transient verdict, with the given number of prior re-drives.
func parkedTransientVolume(retryCount int) types.VolumeStatus {
	vs := types.VolumeStatus{
		State:                      types.CREATING_VOLUME,
		SubState:                   types.VolumeSubStatePrepareDone,
		ClusterStorageTransientErr: true,
		ClusterStorageRetryCount:   retryCount,
	}
	vs.SetErrorWithSource("RolloutDiskToPVC attempts to upload image failed",
		types.VolumeStatus{}, time.Now())
	return vs
}

// TestClusterVolumeRetryActionFor pins the bounded-retry boundary: a parked transient
// volume is re-driven until it has been retried maxClusterVolumeRetries times, after
// which the retry gives up (leaving a terminal error) instead of looping every gc
// tick forever. Anything that is not a parked transient cluster-volume failure is
// skipped.
func TestClusterVolumeRetryActionFor(t *testing.T) {
	// Under the cap: re-drive.
	for _, n := range []int{0, 1, maxClusterVolumeRetries - 1} {
		vs := parkedTransientVolume(n)
		if got := clusterVolumeRetryActionFor(&vs); got != cvRedrive {
			t.Errorf("retryCount=%d: got %d, want cvRedrive(%d)", n, got, cvRedrive)
		}
	}
	// At or beyond the cap: give up (terminal), no more re-drives.
	for _, n := range []int{maxClusterVolumeRetries, maxClusterVolumeRetries + 5} {
		vs := parkedTransientVolume(n)
		if got := clusterVolumeRetryActionFor(&vs); got != cvGiveUp {
			t.Errorf("retryCount=%d: got %d, want cvGiveUp(%d)", n, got, cvGiveUp)
		}
	}
	// Not a retry candidate: skip.
	skips := map[string]func(*types.VolumeStatus){
		"no error":       func(v *types.VolumeStatus) { v.ClearErrorWithSource() },
		"not transient":  func(v *types.VolumeStatus) { v.ClusterStorageTransientErr = false },
		"wrong state":    func(v *types.VolumeStatus) { v.State = types.CREATED_VOLUME },
		"wrong substate": func(v *types.VolumeStatus) { v.SubState = types.VolumeSubStateCreated },
	}
	for name, mutate := range skips {
		vs := parkedTransientVolume(0)
		mutate(&vs)
		if got := clusterVolumeRetryActionFor(&vs); got != cvSkip {
			t.Errorf("%s: got %d, want cvSkip(%d)", name, got, cvSkip)
		}
	}
}
