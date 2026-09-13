// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build faultinjection

package vault

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// Fault injection for the ZFS vault migration, compiled in only under the
// faultinjection build tag (FAULT_INJECTION=y). Production images get the no-op
// wrapper in faultinjection_migration_disabled.go instead.
//
// It exists for the one failure the unit tests cannot reach: power loss inside
// the rename swap. A test can make an error come out of any step by faking the
// storage operations, but only a real interruption tells you whether ZFS's
// rename, and the swap record's fsync, actually survive losing the machine at
// that instant. So the injected fault is not an error — it parks the migration
// in the window and lets the test cut power from outside.
const (
	// vaultMigrationFaultFile names the step to interrupt. It lives on
	// /persist, not under /tmp like the older markers in kubeapi: the migration
	// runs on the first EVE-k boot, and /tmp does not survive the reboot that
	// gets there, so a marker written before the update would be gone by the
	// time it mattered. /config would be worse still — the presence of a file
	// there is measured into PCR14, and PCR14 seals the vault, so arming the
	// fault would change the seal and the vault would fail to unlock for a
	// reason that has nothing to do with the fault.
	vaultMigrationFaultFile = types.PersistStatusDir + "/vault-migration-fault"

	// vaultMigrationFaultReachedFile is written, durably, the moment the named
	// step is reached, so a test watching from the host knows when the device is
	// sitting in the window rather than having to guess at a delay.
	vaultMigrationFaultReachedFile = types.PersistStatusDir + "/vault-migration-fault-reached"

	// faultStepBeforePromote parks the migration after the pre-migration vault
	// has been renamed aside and before the staging zvol takes its place: the
	// window in which the vault path does not exist at all.
	faultStepBeforePromote = "before-promote"

	// vaultMigrationFaultHold bounds the wait, so a test that never cuts power
	// leaves behind a device that completed its migration rather than one parked
	// forever. vaultmgr keeps its watchdog fed across this: the lifecycle
	// operations run on their own goroutine with a StillRunning ticker.
	vaultMigrationFaultHold = 15 * time.Minute
)

// wrapVaultOps arms the fault when the marker names a step, and otherwise hands
// back the storage operations untouched.
func wrapVaultOps(inner zfsVaultOps, log *base.LogObject) zfsVaultOps {
	step := readMigrationFaultStep()
	if step == "" {
		return inner
	}
	log.Noticef("vault migration fault injection armed for step %q", step)
	return faultVaultOps{inner: inner, step: step, log: log}
}

func readMigrationFaultStep() string {
	contents, err := os.ReadFile(vaultMigrationFaultFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}

// faultVaultOps delegates every storage operation to the real ones, parking the
// migration when it reaches the step the marker named.
type faultVaultOps struct {
	inner zfsVaultOps
	step  string
	log   *base.LogObject
}

// RenameDataset parks before the promoting rename when that step is armed. The
// promoting rename is the one moving the staging zvol onto the vault path,
// identified by the pair of names rather than by counting calls.
func (f faultVaultOps) RenameDataset(oldName, newName string) error {
	if f.step == faultStepBeforePromote && oldName == newName+vaultStagingSuffix {
		f.park(oldName, newName)
	}
	return f.inner.RenameDataset(oldName, newName)
}

// park disarms the fault, records that the window was reached, and waits there
// for the test to cut power. Disarming first, durably, is what keeps a power cut
// from re-arming the fault on the next boot and looping.
func (f faultVaultOps) park(oldName, newName string) {
	if err := os.Remove(vaultMigrationFaultFile); err != nil && !os.IsNotExist(err) {
		f.log.Errorf("vault migration fault: cannot disarm %s: %v", vaultMigrationFaultFile, err)
	}
	if err := utils.DirSync(filepath.Dir(vaultMigrationFaultFile)); err != nil {
		f.log.Errorf("vault migration fault: cannot sync %s: %v", types.PersistStatusDir, err)
	}
	if err := utils.WriteRename(vaultMigrationFaultReachedFile,
		[]byte(f.step+" "+oldName+" -> "+newName+"\n")); err != nil {
		f.log.Errorf("vault migration fault: cannot record reaching the window: %v", err)
	}
	f.log.Noticef("vault migration fault: parked at %q before renaming %s onto %s; holding %v",
		f.step, oldName, newName, vaultMigrationFaultHold)
	time.Sleep(vaultMigrationFaultHold)
	f.log.Noticef("vault migration fault: hold expired, continuing the swap")
}

func (f faultVaultOps) DatasetExist(name string) bool { return f.inner.DatasetExist(name) }

func (f faultVaultOps) CreateVaultZvol(name, keyFile string, encrypt bool, sizeBytes uint64) error {
	return f.inner.CreateVaultZvol(name, keyFile, encrypt, sizeBytes)
}

func (f faultVaultOps) CreateEtcdZvol(name, keyFile string, encrypt bool) error {
	return f.inner.CreateEtcdZvol(name, keyFile, encrypt)
}

func (f faultVaultOps) DestroyDataset(name string) error { return f.inner.DestroyDataset(name) }

func (f faultVaultOps) UnmountDataset(name string) error { return f.inner.UnmountDataset(name) }

func (f faultVaultOps) AvailableBytes(name string) (uint64, error) {
	return f.inner.AvailableBytes(name)
}

func (f faultVaultOps) UsedBytes(name string) (uint64, error) { return f.inner.UsedBytes(name) }

func (f faultVaultOps) FormatStagingZvol(name string) error {
	return f.inner.FormatStagingZvol(name)
}

func (f faultVaultOps) MountStaging(name string) (string, error) {
	return f.inner.MountStaging(name)
}

func (f faultVaultOps) UnmountStaging(mountpoint string) error {
	return f.inner.UnmountStaging(mountpoint)
}

func (f faultVaultOps) CopyTree(srcDir, dstDir string) error {
	return f.inner.CopyTree(srcDir, dstDir)
}

func (f faultVaultOps) MountVaultZvol(name string) error { return f.inner.MountVaultZvol(name) }

func (f faultVaultOps) MarkSwapReady(stagingDataset string) error {
	return f.inner.MarkSwapReady(stagingDataset)
}

func (f faultVaultOps) SwapMarkedDataset() (string, error) { return f.inner.SwapMarkedDataset() }

func (f faultVaultOps) ClearSwapMarker() error { return f.inner.ClearSwapMarker() }
