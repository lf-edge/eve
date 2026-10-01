// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func carriedStatus(id string, state types.SwState) types.VolumeStatus {
	return types.VolumeStatus{
		VolumeID:          uuid.FromStringOrNil(id),
		GenerationCounter: 1,
		Encrypted:         true,
		ContentFormat:     zconfig.Format_QCOW2,
		State:             state,
	}
}

const (
	carriedA = "11111111-1111-1111-1111-111111111111"
	carriedB = "22222222-2222-2222-2222-222222222222"
)

// TestPlanKvmCarryDrain covers which carried-over EVE-kvm volumes are
// removed: only those whose PVC holds the data, and those no VolumeStatus has
// claimed for the grace period.
func TestPlanKvmCarryDrain(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	grace := time.Hour
	file := kvmCarried{location: "/persist/vault/volumes-kvm/" + carriedA + "#1.qcow2",
		name: carriedA + "#1.qcow2"}
	zvol := kvmCarried{location: "persist/vault.old/volumes/" + carriedA + ".1",
		name: carriedA + ".1", zvol: true}
	orphan := kvmCarried{location: "persist/vault.old/volumes/" + carriedB + ".1",
		name: carriedB + ".1", zvol: true}

	tests := []struct {
		name        string
		candidate   kvmCarried
		statuses    []types.VolumeStatus
		orphanSince map[string]time.Time
		wantRemove  bool
	}{
		{name: "created file", candidate: file,
			statuses: []types.VolumeStatus{carriedStatus(carriedA, types.CREATED_VOLUME)}, wantRemove: true},
		{name: "created file, status now a PVC", candidate: file,
			statuses: []types.VolumeStatus{func() types.VolumeStatus {
				st := carriedStatus(carriedA, types.CREATED_VOLUME)
				st.ContentFormat = zconfig.Format_PVC
				return st
			}()}, wantRemove: true},
		{name: "file claimed by another generation", candidate: file,
			statuses: []types.VolumeStatus{func() types.VolumeStatus {
				st := carriedStatus(carriedA, types.CREATED_VOLUME)
				st.ContentFormat = zconfig.Format_PVC
				st.GenerationCounter = 2
				return st
			}()}},
		{name: "created zvol", candidate: zvol,
			statuses: []types.VolumeStatus{carriedStatus(carriedA, types.CREATED_VOLUME)}, wantRemove: true},
		{name: "rollout in flight", candidate: zvol,
			statuses: []types.VolumeStatus{carriedStatus(carriedA, types.CREATING_VOLUME)}},
		{name: "rollout failed", candidate: zvol,
			statuses: []types.VolumeStatus{func() types.VolumeStatus {
				st := carriedStatus(carriedA, types.CREATED_VOLUME)
				st.SetError("upload failed", time.Now())
				return st
			}()}},
		{name: "claimed by another generation", candidate: zvol,
			statuses: []types.VolumeStatus{func() types.VolumeStatus {
				st := carriedStatus(carriedA, types.CREATED_VOLUME)
				st.GenerationCounter = 2
				return st
			}()}},
		{name: "orphan first seen", candidate: orphan},
		{name: "orphan within grace", candidate: orphan,
			orphanSince: map[string]time.Time{orphan.location: now.Add(-grace / 2)}},
		{name: "orphan past grace", candidate: orphan,
			orphanSince: map[string]time.Time{orphan.location: now.Add(-grace)}, wantRemove: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			since := tc.orphanSince
			if since == nil {
				since = map[string]time.Time{}
			}
			got := planKvmCarryDrain([]kvmCarried{tc.candidate}, tc.statuses, since, now, grace)
			if tc.wantRemove {
				assert.Equal(t, []kvmCarried{tc.candidate}, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

// TestPlanKvmCarryDrainForgetsClaimed covers that an orphan timer restarts when
// a VolumeStatus claims the volume, and that a vanished candidate is forgotten.
func TestPlanKvmCarryDrainForgetsClaimed(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := kvmCarried{location: "persist/vault.old/volumes/" + carriedA + ".1", name: carriedA + ".1", zvol: true}
	since := map[string]time.Time{c.location: now.Add(-2 * time.Hour), "gone": now}

	got := planKvmCarryDrain([]kvmCarried{c},
		[]types.VolumeStatus{carriedStatus(carriedA, types.CREATING_VOLUME)}, since, now, time.Hour)

	assert.Empty(t, got)
	assert.Empty(t, since)
}

type fakeKvmCarry struct {
	committed bool
	datasets  map[string]bool
	files     map[string][]string
	destroyed []string
	removed   []string
}

type namedEntry string

func (n namedEntry) Name() string               { return string(n) }
func (n namedEntry) IsDir() bool                { return false }
func (n namedEntry) Type() os.FileMode          { return 0 }
func (n namedEntry) Info() (os.FileInfo, error) { return nil, errors.New("not implemented") }

func (f *fakeKvmCarry) install(t *testing.T) {
	orig := kvmCarry
	t.Cleanup(func() { kvmCarry = orig })
	kvmCarry = kvmCarryOps{
		partitionCommitted: func() bool { return f.committed },
		readDir: func(dir string) ([]os.DirEntry, error) {
			names, ok := f.files[dir]
			if !ok {
				return nil, os.ErrNotExist
			}
			var out []os.DirEntry
			for _, n := range names {
				out = append(out, namedEntry(n))
			}
			return out, nil
		},
		removeAll: func(path string) error {
			f.removed = append(f.removed, path)
			return nil
		},
		datasetExists: func(dataset string) bool { return f.datasets[dataset] },
		listZvols: func(dataset string) ([]string, error) {
			var out []string
			for d := range f.datasets {
				if strings.HasPrefix(d, dataset+"/") {
					out = append(out, d)
				}
			}
			return out, nil
		},
		destroyDataset: func(dataset string) error {
			f.destroyed = append(f.destroyed, dataset)
			for d := range f.datasets {
				if d == dataset || strings.HasPrefix(d, dataset+"/") {
					delete(f.datasets, d)
				}
			}
			return nil
		},
	}
}

func newDrainCtx(t *testing.T, statuses ...types.VolumeStatus) *volumemgrContext {
	ctx := initStatusCtx(t)
	ctx.hvTypeKube = true
	ctx.persistType = types.PersistZFS
	ctx.vdiskGCTime = 3600
	for i := range statuses {
		publishVolumeStatus(ctx, &statuses[i])
	}
	return ctx
}

// TestDrainKvmCarriedVolumesWaitsForCommit covers that nothing is removed while
// a reboot can still fall back to EVE-kvm.
func TestDrainKvmCarriedVolumesWaitsForCommit(t *testing.T) {
	zvol := types.KvmParkedVolumeEncryptedZFSDataset + "/" + carriedA + ".1"
	f := &fakeKvmCarry{datasets: map[string]bool{
		types.KvmParkedSealedDataset:             true,
		types.KvmParkedVolumeEncryptedZFSDataset: true,
		zvol:                                     true,
	}}
	f.install(t)
	ctx := newDrainCtx(t, carriedStatus(carriedA, types.CREATED_VOLUME))

	drainKvmCarriedVolumes(ctx)

	assert.Empty(t, f.destroyed)
	assert.True(t, f.datasets[types.KvmParkedSealedDataset])
}

// TestDrainKvmCarriedVolumesDropsTheParkedVault covers a committed ZFS device:
// the consumed zvol goes, and the parked vault goes with the last one.
func TestDrainKvmCarriedVolumesDropsTheParkedVault(t *testing.T) {
	zvolA := types.KvmParkedVolumeEncryptedZFSDataset + "/" + carriedA + ".1"
	zvolB := types.KvmParkedVolumeEncryptedZFSDataset + "/" + carriedB + ".1"
	f := &fakeKvmCarry{committed: true, datasets: map[string]bool{
		types.KvmParkedSealedDataset:             true,
		types.KvmParkedVolumeEncryptedZFSDataset: true,
		zvolA:                                    true,
		zvolB:                                    true,
	}}
	f.install(t)
	ctx := newDrainCtx(t,
		carriedStatus(carriedA, types.CREATED_VOLUME),
		carriedStatus(carriedB, types.CREATING_VOLUME))

	drainKvmCarriedVolumes(ctx)
	assert.Equal(t, []string{zvolA}, f.destroyed)
	assert.True(t, f.datasets[types.KvmParkedSealedDataset], "the parked vault went with a zvol left")

	publishVolumeStatus(ctx, func() *types.VolumeStatus {
		st := carriedStatus(carriedB, types.CREATED_VOLUME)
		return &st
	}())
	drainKvmCarriedVolumes(ctx)
	assert.Equal(t, []string{zvolA, zvolB, types.KvmParkedSealedDataset}, f.destroyed)
}

// TestDrainKvmCarriedVolumesRemovesFiles covers the ext4 side: consumed files
// in the holding and clear directories go, other entries stay.
func TestDrainKvmCarriedVolumesRemovesFiles(t *testing.T) {
	holding := types.VolumeEncryptedDirName + "-kvm"
	f := &fakeKvmCarry{committed: true, files: map[string][]string{
		holding:                  {carriedA + "#1.qcow2"},
		types.VolumeClearDirName: {carriedB + "#1.raw", "not-a-volume"},
	}}
	f.install(t)
	clearB := carriedStatus(carriedB, types.CREATED_VOLUME)
	clearB.Encrypted = false
	clearB.ContentFormat = zconfig.Format_RAW
	ctx := newDrainCtx(t, carriedStatus(carriedA, types.CREATED_VOLUME), clearB)
	ctx.persistType = types.PersistExt4

	drainKvmCarriedVolumes(ctx)

	assert.ElementsMatch(t, []string{
		holding + "/" + carriedA + "#1.qcow2",
		types.VolumeClearDirName + "/" + carriedB + "#1.raw",
	}, f.removed)
	assert.Empty(t, f.destroyed)
}
