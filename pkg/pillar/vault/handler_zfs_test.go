// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFstrimBinaryExists verifies that fstrim is present on PATH. TrimVault
// depends on it; a missing binary would silently fail at runtime on first boot.
func TestFstrimBinaryExists(t *testing.T) {
	_, err := exec.LookPath("fstrim")
	assert.NoError(t, err, "fstrim must be present on PATH; TrimVault will fail without it")
}

// TestVaultNeedsZvolMigration covers the decision that drives whether a
// just-unlocked ZFS vault is migrated from the EVE-kvm filesystem layout to
// the EVE-k zvol layout. Migration is needed only on EVE-k when the existing
// vault is still a filesystem dataset.
func TestVaultNeedsZvolMigration(t *testing.T) {
	tests := []struct {
		name        string
		isKube      bool
		vaultIsZvol bool
		want        bool
	}{
		{name: "kvm fs vault", isKube: false, vaultIsZvol: false, want: false},
		{name: "kvm zvol (n/a)", isKube: false, vaultIsZvol: true, want: false},
		{name: "k carried-over fs vault", isKube: true, vaultIsZvol: false, want: true},
		{name: "k native zvol vault", isKube: true, vaultIsZvol: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := vaultNeedsZvolMigration(tc.isKube, tc.vaultIsZvol); got != tc.want {
				t.Errorf("vaultNeedsZvolMigration(%t, %t) = %t, want %t",
					tc.isKube, tc.vaultIsZvol, got, tc.want)
			}
		})
	}
}

// fakeZFSOps is an in-memory zfsVaultOps: it tracks which datasets exist and
// can fail any single operation, so the migration and recovery paths can be
// exercised without a pool.
type fakeZFSOps struct {
	datasets  map[string]bool
	availFree uint64
	vaultUsed uint64
	// fail maps an operation name to the error it returns; failNth limits that
	// to the n-th call of the operation (1-based, 0 means every call).
	fail    map[string]error
	failNth map[string]int
	calls   map[string]int
	log     []string
}

func newFakeZFSOps(datasets ...string) *fakeZFSOps {
	f := &fakeZFSOps{
		datasets:  make(map[string]bool),
		availFree: 100 << 30,
		vaultUsed: 1 << 30,
		fail:      make(map[string]error),
		failNth:   make(map[string]int),
		calls:     make(map[string]int),
	}
	for _, d := range datasets {
		f.datasets[d] = true
	}
	return f
}

func (f *fakeZFSOps) failOn(op string, nth int) {
	f.fail[op] = fmt.Errorf("injected %s failure", op)
	f.failNth[op] = nth
}

// call records an invocation and returns the injected error if this call is
// the one that should fail.
func (f *fakeZFSOps) call(op string, detail string) error {
	f.calls[op]++
	f.log = append(f.log, op+"("+detail+")")
	err, ok := f.fail[op]
	if !ok {
		return nil
	}
	if nth := f.failNth[op]; nth != 0 && nth != f.calls[op] {
		return nil
	}
	return err
}

func (f *fakeZFSOps) DatasetExist(name string) bool {
	return f.datasets[name]
}

func (f *fakeZFSOps) CreateVaultZvol(name, _ string, _ bool, _ uint64) error {
	if err := f.call("CreateVaultZvol", name); err != nil {
		return err
	}
	f.datasets[name] = true
	return nil
}

func (f *fakeZFSOps) CreateEtcdZvol(name, _ string, _ bool) error {
	if err := f.call("CreateEtcdZvol", name); err != nil {
		return err
	}
	f.datasets[name] = true
	return nil
}

func (f *fakeZFSOps) RenameDataset(oldName, newName string) error {
	if err := f.call("RenameDataset", oldName+"->"+newName); err != nil {
		return err
	}
	delete(f.datasets, oldName)
	f.datasets[newName] = true
	return nil
}

func (f *fakeZFSOps) DestroyDataset(name string) error {
	if err := f.call("DestroyDataset", name); err != nil {
		return err
	}
	delete(f.datasets, name)
	return nil
}

func (f *fakeZFSOps) UnmountDataset(name string) error {
	return f.call("UnmountDataset", name)
}

func (f *fakeZFSOps) AvailableBytes(name string) (uint64, error) {
	if err := f.call("AvailableBytes", name); err != nil {
		return 0, err
	}
	return f.availFree, nil
}

func (f *fakeZFSOps) UsedBytes(name string) (uint64, error) {
	if err := f.call("UsedBytes", name); err != nil {
		return 0, err
	}
	return f.vaultUsed, nil
}

func (f *fakeZFSOps) FormatStagingZvol(name string) error {
	return f.call("FormatStagingZvol", name)
}

func (f *fakeZFSOps) MountStaging(name string) (string, error) {
	if err := f.call("MountStaging", name); err != nil {
		return "", err
	}
	return vaultMigrateMountpoint, nil
}

func (f *fakeZFSOps) UnmountStaging(mountpoint string) error {
	return f.call("UnmountStaging", mountpoint)
}

func (f *fakeZFSOps) CopyTree(srcDir, dstDir string) error {
	return f.call("CopyTree", srcDir+"->"+dstDir)
}

func (f *fakeZFSOps) MountVaultZvol(name string) error {
	return f.call("MountVaultZvol", name)
}

func testZFSHandler(ops zfsVaultOps) *ZFSHandler {
	return &ZFSHandler{
		log: base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234),
		ops: ops,
	}
}

const (
	testVault   = "persist/vault"
	testStaging = testVault + vaultStagingSuffix
	testBackup  = testVault + vaultBackupSuffix
)

// TestRecoverInterruptedVaultMigration covers the states a migration can leave
// its datasets in when it is interrupted mid-swap.
func TestRecoverInterruptedVaultMigration(t *testing.T) {
	tests := []struct {
		name      string
		datasets  []string
		wantVault bool
	}{
		{
			name:      "swap interrupted between the renames",
			datasets:  []string{testStaging, testBackup},
			wantVault: true,
		},
		{
			name:      "swap interrupted, backup already destroyed",
			datasets:  []string{testStaging},
			wantVault: true,
		},
		{
			name:      "only the pre-migration vault survives",
			datasets:  []string{testBackup},
			wantVault: true,
		},
		{
			name:      "vault in place, swap cleanup interrupted",
			datasets:  []string{testVault, testBackup},
			wantVault: true,
		},
		{
			name:      "no leftovers",
			datasets:  []string{testVault},
			wantVault: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeZFSOps(tc.datasets...)
			h := testZFSHandler(ops)

			require.NoError(t, h.recoverInterruptedVaultMigration(testVault))

			assert.Equal(t, tc.wantVault, ops.datasets[testVault])
			assert.False(t, ops.datasets[testStaging], "staging dataset left behind")
			assert.False(t, ops.datasets[testBackup], "backup dataset left behind")
		})
	}
}

// TestMigrateVaultFsToZvolDropsStagingOnError covers the cleanup of the
// staging zvol when the migration fails after creating it. Left behind, it
// holds up to the pool's free space, and a fallback boot to EVE-kvm has no
// migration code to reclaim it.
func TestMigrateVaultFsToZvolDropsStagingOnError(t *testing.T) {
	// Each entry fails one operation of the migration, in the order the
	// migration performs them. nth selects which call of that operation fails,
	// since the swap calls some of them more than once.
	tests := []struct {
		name string
		op   string
		nth  int
	}{
		{name: "format", op: "FormatStagingZvol"},
		{name: "mount staging", op: "MountStaging"},
		{name: "copy", op: "CopyTree"},
		{name: "unmount staging", op: "UnmountStaging"},
		{name: "unmount source vault", op: "UnmountDataset", nth: 1},
		{name: "rename vault to backup", op: "RenameDataset", nth: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeZFSOps(testVault)
			ops.failOn(tc.op, tc.nth)
			h := testZFSHandler(ops)

			err := h.migrateVaultFsToZvol(testVault, "/run/key", true)

			assert.Error(t, err)
			assert.False(t, ops.datasets[testStaging], "staging zvol left behind")
			assert.True(t, ops.datasets[testVault], "source vault lost")
		})
	}
}

// TestMigrateVaultFsToZvolRestoresVaultOnFailedSwap covers a failure of the
// second rename: the vault must not be left absent, since EVE-kvm has no
// recovery path and would create an empty vault over it on a fallback boot.
func TestMigrateVaultFsToZvolRestoresVaultOnFailedSwap(t *testing.T) {
	ops := newFakeZFSOps(testVault)
	ops.failOn("RenameDataset", 2)
	h := testZFSHandler(ops)

	err := h.migrateVaultFsToZvol(testVault, "/run/key", true)

	assert.Error(t, err)
	assert.True(t, ops.datasets[testVault], "vault left absent after a failed swap")
	assert.False(t, ops.datasets[testBackup])
	assert.False(t, ops.datasets[testStaging], "staging zvol left behind")
}

// TestMigrateVaultFsToZvolDeclinedLeavesNothing covers a migration declined
// for lack of free space: neither the staging zvol nor the etcd zvol may be
// created, since every following boot retries and a fallback to EVE-kvm keeps
// whatever was left.
func TestMigrateVaultFsToZvolDeclinedLeavesNothing(t *testing.T) {
	ops := newFakeZFSOps(testVault)
	ops.availFree = 1 << 30
	ops.vaultUsed = 8 << 30
	h := testZFSHandler(ops)

	err := h.migrateVaultFsToZvol(testVault, "/run/key", true)

	assert.ErrorContains(t, err, "insufficient free space")
	assert.False(t, ops.datasets[testStaging])
	assert.False(t, ops.datasets[types.EtcdZvol])
}

// TestMigrateVaultFsToZvolSwap covers the successful migration: the staging
// zvol ends up as the vault and the pre-migration vault is gone.
func TestMigrateVaultFsToZvolSwap(t *testing.T) {
	ops := newFakeZFSOps(testVault)
	h := testZFSHandler(ops)

	require.NoError(t, h.migrateVaultFsToZvol(testVault, "/run/key", true))

	assert.True(t, ops.datasets[testVault])
	assert.True(t, ops.datasets[types.EtcdZvol])
	assert.False(t, ops.datasets[testStaging])
	assert.False(t, ops.datasets[testBackup])
	assert.Equal(t, 1, ops.calls["MountVaultZvol"])
}
