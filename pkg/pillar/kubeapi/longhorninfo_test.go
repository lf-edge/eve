// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func snap(name string, size int64, markRemoved bool) lhv1beta2.Snapshot {
	return lhv1beta2.Snapshot{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     lhv1beta2.SnapshotStatus{Size: size, MarkRemoved: markRemoved},
	}
}

func TestSumSnapshotBytes(t *testing.T) {
	vol := "pvc-abc"
	tests := []struct {
		name  string
		snaps []lhv1beta2.Snapshot
		want  int64
	}{
		{
			name:  "empty list",
			snaps: nil,
			want:  0,
		},
		{
			name:  "volume-head excluded",
			snaps: []lhv1beta2.Snapshot{snap(vol+"-volume-head", 1000, false)},
			want:  0,
		},
		{
			name:  "single real snapshot",
			snaps: []lhv1beta2.Snapshot{snap("snap-1", 500, false)},
			want:  500,
		},
		{
			name: "MarkRemoved snapshot included",
			snaps: []lhv1beta2.Snapshot{
				snap("snap-old", 4096, true), // queued for GC but still on disk
				snap("snap-new", 256, false),
			},
			want: 4352,
		},
		{
			name: "head excluded, reals summed",
			snaps: []lhv1beta2.Snapshot{
				snap(vol+"-volume-head", 9999, false),
				snap("snap-1", 100, false),
				snap("snap-2", 200, false),
			},
			want: 300,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sumSnapshotBytes(tc.snaps); got != tc.want {
				t.Errorf("sumSnapshotBytes: got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestReplicaModeProgress(t *testing.T) {
	tests := []struct {
		name            string
		inModeMap       bool
		mode            lhv1beta2.ReplicaMode
		hasRebuildEntry bool
		rebuildProgress int
		wantPct         uint8
		wantStatus      types.StorageVolumeReplicaStatus
		wantConsistent  bool
	}{
		{
			name:           "not in mode map: not yet registered with engine",
			inModeMap:      false,
			wantPct:        0,
			wantStatus:     types.StorageVolumeReplicaStatusOnline,
			wantConsistent: false,
		},
		{
			name:           "RW: fully synced — only state that means 100%",
			inModeMap:      true,
			mode:           lhv1beta2.ReplicaModeRW,
			wantPct:        100,
			wantStatus:     types.StorageVolumeReplicaStatusOnline,
			wantConsistent: true,
		},
		{
			// This is the false-100% bug case: WO with no RebuildStatus entry yet.
			// Old code returned 100% here; correct behavior is 0% (queued, not started).
			name:            "WO without rebuild entry: transfer queued, not started",
			inModeMap:       true,
			mode:            lhv1beta2.ReplicaModeWO,
			hasRebuildEntry: false,
			wantPct:         0,
			wantStatus:      types.StorageVolumeReplicaStatusRebuilding,
			wantConsistent:  false,
		},
		{
			name:            "WO with rebuild entry 0%: transfer just started",
			inModeMap:       true,
			mode:            lhv1beta2.ReplicaModeWO,
			hasRebuildEntry: true,
			rebuildProgress: 0,
			wantPct:         0,
			wantStatus:      types.StorageVolumeReplicaStatusRebuilding,
			wantConsistent:  false,
		},
		{
			name:            "WO with rebuild entry 47%: transfer in progress",
			inModeMap:       true,
			mode:            lhv1beta2.ReplicaModeWO,
			hasRebuildEntry: true,
			rebuildProgress: 47,
			wantPct:         47,
			wantStatus:      types.StorageVolumeReplicaStatusRebuilding,
			wantConsistent:  false,
		},
		{
			// WO at 100% means the transfer completed but the engine has not yet
			// promoted the replica to RW. It is still not consistent.
			name:            "WO with rebuild entry 100%: transfer done, not yet promoted",
			inModeMap:       true,
			mode:            lhv1beta2.ReplicaModeWO,
			hasRebuildEntry: true,
			rebuildProgress: 100,
			wantPct:         100,
			wantStatus:      types.StorageVolumeReplicaStatusRebuilding,
			wantConsistent:  false,
		},
		{
			name:           "ERR: failed replica",
			inModeMap:      true,
			mode:           lhv1beta2.ReplicaModeERR,
			wantPct:        0,
			wantStatus:     types.StorageVolumeReplicaStatusFailed,
			wantConsistent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPct, gotStatus, gotConsistent := replicaModeProgress(
				tc.inModeMap, tc.mode, tc.hasRebuildEntry, tc.rebuildProgress,
			)
			if gotPct != tc.wantPct {
				t.Errorf("percentage: got %d, want %d", gotPct, tc.wantPct)
			}
			if gotStatus != tc.wantStatus {
				t.Errorf("status: got %v, want %v", gotStatus, tc.wantStatus)
			}
			if gotConsistent != tc.wantConsistent {
				t.Errorf("isConsistent: got %v, want %v", gotConsistent, tc.wantConsistent)
			}
		})
	}
}

func TestRobustnessSubstate(t *testing.T) {
	H := types.StorageVolumeRobustnessHealthy
	D := types.StorageVolumeRobustnessDegraded
	F := types.StorageVolumeRobustnessFaulted
	U := types.StorageVolumeRobustnessUnknown

	tests := []struct {
		name         string
		robustness   types.StorageVolumeRobustness
		online       int
		consistent   int
		wantSubstate types.StorageHealthStatus
	}{
		{
			name:         "healthy",
			robustness:   H,
			wantSubstate: types.StorageHealthStatusHealthy,
		},
		{
			name:         "faulted",
			robustness:   F,
			wantSubstate: types.StorageHealthStatusFailed,
		},
		{
			name:         "unknown robustness",
			robustness:   U,
			wantSubstate: types.StorageHealthStatusUnknown,
		},
		{
			name:         "degraded online=1 (not replicating)",
			robustness:   D,
			online:       1,
			consistent:   0,
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableNotReplicating,
		},
		{
			name:         "degraded online=2 consistent=1 (replicating)",
			robustness:   D,
			online:       2,
			consistent:   1,
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
		},
		{
			name:         "degraded online=2 consistent=2 (2 up, not replicating)",
			robustness:   D,
			online:       2,
			consistent:   2,
			wantSubstate: types.StorageHealthStatusDegraded2ReplicaAvailableNotReplicating,
		},
		{
			name:         "degraded online=3 consistent=1 (replicating)",
			robustness:   D,
			online:       3,
			consistent:   1,
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
		},
		{
			name:         "degraded online=3 consistent=2 (2 up, replicating)",
			robustness:   D,
			online:       3,
			consistent:   2,
			wantSubstate: types.StorageHealthStatusDegraded2ReplicaAvailableReplicating,
		},
		{
			name:         "degraded unhandled combo (online=2 consistent=0) → unknown",
			robustness:   D,
			online:       2,
			consistent:   0,
			wantSubstate: types.StorageHealthStatusUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := robustnessSubstate(tc.robustness, tc.online, tc.consistent)
			if got != tc.wantSubstate {
				t.Errorf("robustnessSubstate: got %v, want %v", got, tc.wantSubstate)
			}
		})
	}
}
