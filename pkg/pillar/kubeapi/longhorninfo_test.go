// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"context"
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	lhv1beta2 "github.com/longhorn/longhorn-manager/k8s/pkg/apis/longhorn/v1beta2"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// -- mock types for populateKVIInner --

type funcPVCGetter struct {
	fn func(string) (*corev1.PersistentVolumeClaim, error)
}

func (m funcPVCGetter) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.PersistentVolumeClaim, error) {
	return m.fn(name)
}

type funcLHVolGetter struct {
	fn func(string) (*lhv1beta2.Volume, error)
}

func (m funcLHVolGetter) Get(_ context.Context, name string, _ metav1.GetOptions) (*lhv1beta2.Volume, error) {
	return m.fn(name)
}

type funcLHReplicaLister struct {
	fn func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error)
}

func (m funcLHReplicaLister) List(_ context.Context, opts metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
	return m.fn(opts)
}

type funcLHEngineGetter struct {
	fn func(string) (*lhv1beta2.Engine, error)
}

func (m funcLHEngineGetter) Get(_ context.Context, name string, _ metav1.GetOptions) (*lhv1beta2.Engine, error) {
	return m.fn(name)
}

// -- helper constructors --

func fakePVC(pvcName, volName string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: volName},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
}

func fakeLHVol(robustness lhv1beta2.VolumeRobustness) *lhv1beta2.Volume {
	return &lhv1beta2.Volume{
		Status: lhv1beta2.VolumeStatus{
			Robustness: robustness,
			State:      lhv1beta2.VolumeStateAttached,
		},
	}
}

// fakeReplica creates a replica with OwnerID and CurrentImage set (has fs backing).
func fakeReplica(name, engineName, ip string, port int, state lhv1beta2.InstanceState) lhv1beta2.Replica {
	return lhv1beta2.Replica{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       lhv1beta2.ReplicaSpec{EngineName: engineName},
		Status: lhv1beta2.ReplicaStatus{
			InstanceStatus: lhv1beta2.InstanceStatus{
				OwnerID:      "node1",
				CurrentImage: "longhorn-engine:latest",
				IP:           ip,
				Port:         port,
				CurrentState: state,
			},
		},
	}
}

func fakeEngine(
	name string,
	modeMap map[string]lhv1beta2.ReplicaMode,
	rebuildStatus map[string]*lhv1beta2.RebuildStatus,
	addrMap map[string]string,
) *lhv1beta2.Engine {
	return &lhv1beta2.Engine{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: lhv1beta2.EngineStatus{
			ReplicaModeMap:           modeMap,
			RebuildStatus:            rebuildStatus,
			CurrentReplicaAddressMap: addrMap,
		},
	}
}

func findReplica(kvi *types.KubeVolumeInfo, name string) *types.KubeVolumeReplicaInfo {
	for i := range kvi.Replicas {
		if kvi.Replicas[i].Name == name {
			return &kvi.Replicas[i]
		}
	}
	return nil
}

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
			wantStatus:     types.StorageVolumeReplicaStatusUnknown,
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
			// WO with no RebuildStatus entry: transfer is queued but not yet started.
			// There is no progress to report; the replica is not consistent.
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
		{
			// Longhorn volume is Healthy but one Running replica is not yet confirmed
			// RW in ReplicaModeMap (engine-lag window). Guard falls through to Degraded
			// branch to prevent a false Healthy signal.
			name:         "healthy volume with unconfirmed replica falls through to degraded",
			robustness:   H,
			online:       2,
			consistent:   1,
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
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

func TestReplicaHasNoFsBacking(t *testing.T) {
	tests := []struct {
		name    string
		replica lhv1beta2.Replica
		want    bool
	}{
		{
			name:    "all empty: no backing",
			replica: lhv1beta2.Replica{},
			want:    true,
		},
		{
			name: "OwnerID set: has backing",
			replica: lhv1beta2.Replica{
				Status: lhv1beta2.ReplicaStatus{
					InstanceStatus: lhv1beta2.InstanceStatus{OwnerID: "node1"},
				},
			},
			want: false,
		},
		{
			name: "InstanceManagerName set: has backing",
			replica: lhv1beta2.Replica{
				Status: lhv1beta2.ReplicaStatus{
					InstanceStatus: lhv1beta2.InstanceStatus{InstanceManagerName: "im-1"},
				},
			},
			want: false,
		},
		{
			name: "CurrentImage set: has backing",
			replica: lhv1beta2.Replica{
				Status: lhv1beta2.ReplicaStatus{
					InstanceStatus: lhv1beta2.InstanceStatus{CurrentImage: "longhorn-engine:latest"},
				},
			},
			want: false,
		},
		{
			name: "all three set: has backing",
			replica: lhv1beta2.Replica{
				Status: lhv1beta2.ReplicaStatus{
					InstanceStatus: lhv1beta2.InstanceStatus{
						OwnerID:             "node1",
						InstanceManagerName: "im-1",
						CurrentImage:        "longhorn-engine:latest",
					},
				},
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := replicaHasNoFsBacking(tc.replica); got != tc.want {
				t.Errorf("replicaHasNoFsBacking = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPopulateKVIInner(t *testing.T) {
	const (
		testPVC   = "test-pvc"
		testVol   = "test-vol"
		eng1      = "engine-1"
		r1RawAddr = "10.0.0.1:8502" // currentReplicaAddressMap value format (no tcp://)
		r2RawAddr = "10.0.0.2:8502"
		r2TcpAddr = "tcp://10.0.0.2:8502" // rebuildStatus key format (with tcp://)
	)

	noSnapBytes := func(string) (int64, error) { return 0, nil }

	r1 := fakeReplica("r1", eng1, "10.0.0.1", 8502, lhv1beta2.InstanceStateRunning)
	r2 := fakeReplica("r2", eng1, "10.0.0.2", 8502, lhv1beta2.InstanceStateRunning)

	stdPVC := funcPVCGetter{fn: func(string) (*corev1.PersistentVolumeClaim, error) {
		return fakePVC(testPVC, testVol), nil
	}}

	lhVolHealthy := funcLHVolGetter{fn: func(string) (*lhv1beta2.Volume, error) {
		return fakeLHVol(lhv1beta2.VolumeRobustnessHealthy), nil
	}}
	lhVolDegraded := funcLHVolGetter{fn: func(string) (*lhv1beta2.Volume, error) {
		return fakeLHVol(lhv1beta2.VolumeRobustnessDegraded), nil
	}}

	tests := []struct {
		name         string
		pvcs         pvcGetter
		lhVols       lhVolumeGetter
		replicas     lhReplicaLister
		engines      lhEngineGetter
		wantSubstate types.StorageHealthStatus
		wantErr      bool
		checkFn      func(*testing.T, *types.KubeVolumeInfo)
	}{
		{
			// ReplicaModeMap must be looked up by replica name; CurrentReplicaAddressMap
			// provides the name→address mapping for RebuildStatus lookups only.
			name:   "2 RW replicas Degraded vol - modeMap keyed by replica name",
			pvcs:   stdPVC,
			lhVols: lhVolDegraded,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW, "r2": lhv1beta2.ReplicaModeRW},
					nil,
					map[string]string{"r1": r1RawAddr, "r2": r2RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusDegraded2ReplicaAvailableNotReplicating,
		},
		{
			name:   "2 RW replicas Healthy",
			pvcs:   stdPVC,
			lhVols: lhVolHealthy,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW, "r2": lhv1beta2.ReplicaModeRW},
					nil,
					map[string]string{"r1": r1RawAddr, "r2": r2RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusHealthy,
		},
		{
			// A WO replica with no RebuildStatus entry is queued but not yet
			// transferring; it must not be counted as consistent (0% Rebuilding).
			name:   "WO no RebuildStatus entry",
			pvcs:   stdPVC,
			lhVols: lhVolDegraded,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW, "r2": lhv1beta2.ReplicaModeWO},
					nil,
					map[string]string{"r1": r1RawAddr, "r2": r2RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				r := findReplica(kvi, "r2")
				if r == nil {
					t.Fatal("r2 not found")
				}
				if r.Status != types.StorageVolumeReplicaStatusRebuilding {
					t.Errorf("r2.Status = %v, want Rebuilding", r.Status)
				}
				if r.RebuildProgressPercentage != 0 {
					t.Errorf("r2.RebuildProgressPercentage = %d, want 0", r.RebuildProgressPercentage)
				}
			},
		},
		{
			name:   "WO RebuildStatus 47%",
			pvcs:   stdPVC,
			lhVols: lhVolDegraded,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW, "r2": lhv1beta2.ReplicaModeWO},
					map[string]*lhv1beta2.RebuildStatus{r2TcpAddr: {Progress: 47}},
					map[string]string{"r1": r1RawAddr, "r2": r2RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				r := findReplica(kvi, "r2")
				if r == nil {
					t.Fatal("r2 not found")
				}
				if r.RebuildProgressPercentage != 47 {
					t.Errorf("r2.RebuildProgressPercentage = %d, want 47", r.RebuildProgressPercentage)
				}
			},
		},
		{
			// Transfer complete but engine has not yet promoted the replica to RW.
			// It is still not consistent.
			name:   "WO RebuildStatus 100% not yet promoted",
			pvcs:   stdPVC,
			lhVols: lhVolDegraded,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW, "r2": lhv1beta2.ReplicaModeWO},
					map[string]*lhv1beta2.RebuildStatus{r2TcpAddr: {Progress: 100}},
					map[string]string{"r1": r1RawAddr, "r2": r2RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				r := findReplica(kvi, "r2")
				if r == nil {
					t.Fatal("r2 not found")
				}
				if r.Status != types.StorageVolumeReplicaStatusRebuilding {
					t.Errorf("r2.Status = %v, want Rebuilding", r.Status)
				}
				if r.RebuildProgressPercentage != 100 {
					t.Errorf("r2.RebuildProgressPercentage = %d, want 100", r.RebuildProgressPercentage)
				}
			},
		},
		{
			// r2 absent from CurrentReplicaAddressMap; code falls back to constructing
			// IP:Port from replica status fields, prepends tcp:// for RebuildStatus lookup,
			// and looks up ReplicaModeMap by replica name regardless.
			name:   "replica not in CurrentReplicaAddressMap fallback",
			pvcs:   stdPVC,
			lhVols: lhVolDegraded,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW, "r2": lhv1beta2.ReplicaModeWO},
					map[string]*lhv1beta2.RebuildStatus{r2TcpAddr: {Progress: 50}},
					map[string]string{"r1": r1RawAddr}, // r2 absent
				), nil
			}},
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableReplicating,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				r := findReplica(kvi, "r2")
				if r == nil {
					t.Fatal("r2 not found")
				}
				if r.RebuildProgressPercentage != 50 {
					t.Errorf("r2.RebuildProgressPercentage = %d, want 50", r.RebuildProgressPercentage)
				}
			},
		},
		{
			// No-backing replica has no OwnerID/InstanceManagerName/CurrentImage set.
			// It should be skipped entirely and not counted toward replicas or onlineReps.
			name:   "no-backing replica skipped one RW",
			pvcs:   stdPVC,
			lhVols: lhVolHealthy,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				noBacking := lhv1beta2.Replica{ObjectMeta: metav1.ObjectMeta{Name: "r2-no-backing"}}
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, noBacking}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW},
					nil,
					map[string]string{"r1": r1RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusHealthy,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				if len(kvi.Replicas) != 1 {
					t.Errorf("len(Replicas) = %d, want 1 (no-backing replica must be excluded)", len(kvi.Replicas))
				}
			},
		},
		{
			// Error-state replica gets Failed status but does not contribute to onlineReps.
			// If Longhorn marks the volume Healthy (e.g. 3-replica setup with quorum), the
			// substate is still Healthy.
			name:   "one replica error state volume healthy",
			pvcs:   stdPVC,
			lhVols: lhVolHealthy,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				r2err := fakeReplica("r2", eng1, "10.0.0.2", 8502, lhv1beta2.InstanceStateError)
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1, r2err}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW},
					nil,
					map[string]string{"r1": r1RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusHealthy,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				r := findReplica(kvi, "r2")
				if r == nil {
					t.Fatal("r2 not found")
				}
				if r.Status != types.StorageVolumeReplicaStatusFailed {
					t.Errorf("r2.Status = %v, want Failed", r.Status)
				}
			},
		},
		{
			// Regression: an offline (Stopped) replica must report the node its
			// data lives on (Spec.NodeID), not Status.OwnerID. When the data node
			// is down, Longhorn reassigns Status.OwnerID to a surviving manager
			// node, so sourcing OwnerNode from OwnerID would misattribute the
			// offline replica to the wrong node. A running replica keeps reporting
			// its own node.
			name:   "offline replica reports data node not owner survivor",
			pvcs:   stdPVC,
			lhVols: lhVolDegraded,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				// OwnerID is set to a different node than NodeID on BOTH replicas
				// so either assertion below fails if OwnerNode is sourced from
				// Status.OwnerID instead of Spec.NodeID.
				rRun := fakeReplica("r1", eng1, "10.0.0.1", 8502, lhv1beta2.InstanceStateRunning)
				rRun.Spec.NodeID = "node-a"
				rRun.Status.OwnerID = "node-survivor"
				rOffline := fakeReplica("r2", eng1, "10.0.0.2", 8502, lhv1beta2.InstanceStateStopped)
				rOffline.Spec.NodeID = "node-b"           // data placement (down node)
				rOffline.Status.OwnerID = "node-survivor" // survivor manager reconciling the CR
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{rRun, rOffline}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return fakeEngine(eng1,
					map[string]lhv1beta2.ReplicaMode{"r1": lhv1beta2.ReplicaModeRW},
					nil,
					map[string]string{"r1": r1RawAddr},
				), nil
			}},
			wantSubstate: types.StorageHealthStatusDegraded1ReplicaAvailableNotReplicating,
			checkFn: func(t *testing.T, kvi *types.KubeVolumeInfo) {
				rRun := findReplica(kvi, "r1")
				if rRun == nil {
					t.Fatal("r1 not found")
				}
				if rRun.OwnerNode != "node-a" {
					t.Errorf("r1.OwnerNode = %q, want %q", rRun.OwnerNode, "node-a")
				}
				rOff := findReplica(kvi, "r2")
				if rOff == nil {
					t.Fatal("r2 not found")
				}
				if rOff.Status != types.StorageVolumeReplicaStatusOffline {
					t.Errorf("r2.Status = %v, want Offline", rOff.Status)
				}
				if rOff.OwnerNode != "node-b" {
					t.Errorf("r2.OwnerNode = %q, want %q (data node, not owner survivor)", rOff.OwnerNode, "node-b")
				}
			},
		},
		{
			name:   "engine fetch error",
			pvcs:   stdPVC,
			lhVols: lhVolHealthy,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) {
				return &lhv1beta2.ReplicaList{Items: []lhv1beta2.Replica{r1}}, nil
			}},
			engines: funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) {
				return nil, errors.New("engine not found")
			}},
			wantErr: true,
		},
		{
			name: "PVC not found",
			pvcs: funcPVCGetter{fn: func(string) (*corev1.PersistentVolumeClaim, error) {
				return nil, errors.New("pvc not found")
			}},
			lhVols:   lhVolHealthy,
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) { return &lhv1beta2.ReplicaList{}, nil }},
			engines:  funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) { return nil, nil }},
			wantErr:  true,
		},
		{
			name: "LH volume not found",
			pvcs: stdPVC,
			lhVols: funcLHVolGetter{fn: func(string) (*lhv1beta2.Volume, error) {
				return nil, errors.New("vol not found")
			}},
			replicas: funcLHReplicaLister{fn: func(metav1.ListOptions) (*lhv1beta2.ReplicaList, error) { return &lhv1beta2.ReplicaList{}, nil }},
			engines:  funcLHEngineGetter{fn: func(string) (*lhv1beta2.Engine, error) { return nil, nil }},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kvi := &types.KubeVolumeInfo{Name: testPVC}
			result, err := populateKVIInner(
				context.Background(),
				kvi,
				tc.pvcs,
				tc.lhVols,
				tc.replicas,
				tc.engines,
				noSnapBytes,
			)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.RobustnessSubstate != tc.wantSubstate {
				t.Errorf("RobustnessSubstate = %v, want %v", result.RobustnessSubstate, tc.wantSubstate)
			}
			if tc.checkFn != nil {
				tc.checkFn(t, result)
			}
		})
	}
}

// -- mock for setLonghornNodeDiskReservedInner --

type funcLHNodeGetUpdater struct {
	getFn    func(string) (*lhv1beta2.Node, error)
	updateFn func(*lhv1beta2.Node) (*lhv1beta2.Node, error)
}

func (m funcLHNodeGetUpdater) Get(_ context.Context, name string, _ metav1.GetOptions) (*lhv1beta2.Node, error) {
	return m.getFn(name)
}

func (m funcLHNodeGetUpdater) Update(_ context.Context, node *lhv1beta2.Node, _ metav1.UpdateOptions) (*lhv1beta2.Node, error) {
	return m.updateFn(node)
}

func lhNodeWithDisks(reserved int64) *lhv1beta2.Node {
	return &lhv1beta2.Node{
		Spec: lhv1beta2.NodeSpec{
			Disks: map[string]lhv1beta2.DiskSpec{
				"disk-0": {StorageReserved: reserved},
			},
		},
	}
}

func schedulableCondition(status lhv1beta2.ConditionStatus) lhv1beta2.Condition {
	return lhv1beta2.Condition{
		Type:   lhv1beta2.NodeConditionTypeSchedulable,
		Status: status,
	}
}

func TestSetLonghornNodeDiskReservedInner(t *testing.T) {
	const (
		nodeName     = "test-node"
		wantReserved = int64(10 * 1024 * 1024 * 1024)
		alreadySet   = wantReserved
		differentVal = int64(5 * 1024 * 1024 * 1024)
	)

	nodeNotFound := k8serrors.NewNotFound(schema.GroupResource{Resource: "nodes"}, nodeName)

	tests := []struct {
		name        string
		getFn       func(string) (*lhv1beta2.Node, error)
		updateFn    func(*lhv1beta2.Node) (*lhv1beta2.Node, error)
		wantApplied bool
		wantErr     bool
		// updateCalled asserts whether Update was (or was not) invoked.
		wantUpdateCalled bool
	}{
		{
			// Non-schedulable node (tie-breaker): reservation is not needed and
			// the Longhorn admission webhook would reject any update. Return true
			// so the caller stops retrying.
			name: "non-schedulable node returns true without updating",
			getFn: func(string) (*lhv1beta2.Node, error) {
				node := lhNodeWithDisks(differentVal)
				node.Status.Conditions = []lhv1beta2.Condition{
					schedulableCondition(lhv1beta2.ConditionStatusFalse),
				}
				return node, nil
			},
			updateFn:         func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) { return n, nil },
			wantApplied:      true,
			wantErr:          false,
			wantUpdateCalled: false,
		},
		{
			// Schedulable condition present and True: normal node, proceeds to disk check.
			name: "schedulable=True node with correct reservation is a no-op",
			getFn: func(string) (*lhv1beta2.Node, error) {
				node := lhNodeWithDisks(alreadySet)
				node.Status.Conditions = []lhv1beta2.Condition{
					schedulableCondition(lhv1beta2.ConditionStatusTrue),
				}
				return node, nil
			},
			updateFn:         func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) { return n, nil },
			wantApplied:      true,
			wantErr:          false,
			wantUpdateCalled: false,
		},
		{
			// No schedulable condition at all (node not yet registered by Longhorn): treat as
			// schedulable and proceed to disk check.
			name: "no schedulable condition, reservation already set — no-op",
			getFn: func(string) (*lhv1beta2.Node, error) {
				return lhNodeWithDisks(alreadySet), nil
			},
			updateFn:         func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) { return n, nil },
			wantApplied:      true,
			wantErr:          false,
			wantUpdateCalled: false,
		},
		{
			// Disks have the wrong reservation: Update must be called with the
			// corrected value and the function must return (true, nil).
			name: "disks need update — Update called with corrected value",
			getFn: func(string) (*lhv1beta2.Node, error) {
				return lhNodeWithDisks(differentVal), nil
			},
			updateFn: func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) {
				for _, disk := range n.Spec.Disks {
					if disk.StorageReserved != wantReserved {
						return nil, errors.New("disk not updated to wantReserved")
					}
				}
				return n, nil
			},
			wantApplied:      true,
			wantErr:          false,
			wantUpdateCalled: true,
		},
		{
			// Node object not yet created by Longhorn: signal retry with (false, nil).
			name: "node not found returns false without error",
			getFn: func(string) (*lhv1beta2.Node, error) {
				return nil, nodeNotFound
			},
			updateFn:         func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) { return n, nil },
			wantApplied:      false,
			wantErr:          false,
			wantUpdateCalled: false,
		},
		{
			name: "Get returns non-NotFound error",
			getFn: func(string) (*lhv1beta2.Node, error) {
				return nil, errors.New("kube api unavailable")
			},
			updateFn:         func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) { return n, nil },
			wantApplied:      false,
			wantErr:          true,
			wantUpdateCalled: false,
		},
		{
			name: "Update returns error",
			getFn: func(string) (*lhv1beta2.Node, error) {
				return lhNodeWithDisks(differentVal), nil
			},
			updateFn: func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) {
				return nil, errors.New("webhook denied")
			},
			wantApplied:      false,
			wantErr:          true,
			wantUpdateCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updateCalled := false
			wrappedUpdate := func(n *lhv1beta2.Node) (*lhv1beta2.Node, error) {
				updateCalled = true
				return tc.updateFn(n)
			}
			mock := funcLHNodeGetUpdater{getFn: tc.getFn, updateFn: wrappedUpdate}

			applied, err := setLonghornNodeDiskReservedInner(
				context.Background(), nodeName, wantReserved, mock)

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if applied != tc.wantApplied {
				t.Errorf("applied = %v, want %v", applied, tc.wantApplied)
			}
			if updateCalled != tc.wantUpdateCalled {
				t.Errorf("updateCalled = %v, want %v", updateCalled, tc.wantUpdateCalled)
			}
		})
	}
}
