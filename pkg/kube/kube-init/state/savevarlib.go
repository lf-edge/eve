// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// KubeSaveVarLib is the backup location on the persistent volume
// where /var/lib/ is snapshotted before a destructive cluster-mode
// transition. Lives under /persist/vault so the contents are
// encrypted at rest alongside the rest of kube state. Older EVE
// images wrote to /persist/kube-save-var-lib — MigrateVarLib
// relocates it on first boot after upgrade.
const KubeSaveVarLib = "/persist/vault/kube-save-var-lib"

// legacyKubeSaveVarLib is the pre-vault location. Read-only —
// MigrateVarLib copies its contents to KubeSaveVarLib and removes
// the source. New writes go straight to KubeSaveVarLib.
const legacyKubeSaveVarLib = "/persist/kube-save-var-lib"

// MigrateVarLib relocates a pre-vault kube-save-var-lib backup to
// the new vault-backed location, then removes the legacy directory.
// No-op when either (a) the legacy directory does not exist or (b)
// the new location already has content (a prior boot already
// migrated). Vault must be available before this is called.
//
// The copy is recursive because src and dst may sit on different
// filesystems (legacy ext4 vs vault). copyTree handles symlinks
// and permission bits via `cp -a`.
//
// Addresses upstream commit 647a03b2d ("Move kube-save-var-lib
// under vault").
func MigrateVarLib() error {
	if _, err := os.Stat(legacyKubeSaveVarLib); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", legacyKubeSaveVarLib, err)
	}
	// If the vault location already exists, the migration ran on a
	// prior boot. Just remove the legacy directory so we don't keep
	// rechecking it forever.
	if _, err := os.Stat(KubeSaveVarLib); err == nil {
		log.Printf("state: legacy and vault kube-save-var-lib both present; "+
			"removing legacy %s", legacyKubeSaveVarLib)
		return os.RemoveAll(legacyKubeSaveVarLib)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", KubeSaveVarLib, err)
	}

	log.Printf("state: migrating kube-save-var-lib %s -> %s",
		legacyKubeSaveVarLib, KubeSaveVarLib)
	if err := copyTree(legacyKubeSaveVarLib+"/.",
		KubeSaveVarLib+"/", "migrate"); err != nil {
		return err
	}
	if err := os.RemoveAll(legacyKubeSaveVarLib); err != nil {
		// Migration succeeded; legacy cleanup failure is
		// recoverable (next boot will see both and re-clean).
		log.Printf("WARNING: state: remove legacy %s after migrate: %v",
			legacyKubeSaveVarLib, err)
	}
	return nil
}

// SaveVarLib snapshots /var/lib/ to KubeSaveVarLib so a destructive
// cluster-mode transition can be rolled back. The contents are
// staged into a `<dst>.tmp` directory and renamed into place on
// success — a failed cp does not leave a half-populated backup that
// a later RestoreVarLib could silently apply.
//
// Returns an error wrapping os.ErrNotExist if /var/lib itself is
// missing — callers should treat that as "nothing to save".
func SaveVarLib() error {
	return saveVarLibTo("/var/lib", KubeSaveVarLib)
}

// RestoreVarLib copies the contents of KubeSaveVarLib back into
// /var/lib/. Returns an error that unwraps to os.ErrNotExist if the
// backup directory does not exist — callers should treat that as
// "nothing to restore" rather than a hard failure.
func RestoreVarLib() error {
	return restoreVarLibFrom(KubeSaveVarLib, "/var/lib")
}

// saveVarLibTo / restoreVarLibFrom are the inner halves of the
// public pair, with paths injected so tests can run against temp
// dirs.
func saveVarLibTo(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("save /var/lib: source %s missing: %w",
				src, err)
		}
		return fmt.Errorf("stat source %s: %w", src, err)
	}
	staging := dst + ".tmp"
	// Wipe any prior staging dir so a previous failed run doesn't
	// contaminate this one.
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("save: clean staging %s: %w", staging, err)
	}
	if err := copyTree(src+"/.", staging+"/", "save"); err != nil {
		// Make sure we don't leak a half-populated staging dir on
		// failure — RestoreVarLib must never see one.
		_ = os.RemoveAll(staging)
		return err
	}
	// Atomic-ish swap: remove old backup, rename staging into place.
	if err := os.RemoveAll(dst); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("save: remove prior backup %s: %w", dst, err)
	}
	if err := os.Rename(staging, dst); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("save: rename %s -> %s: %w", staging, dst, err)
	}
	return nil
}

func restoreVarLibFrom(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("restore /var/lib: backup %s missing: %w",
				src, err)
		}
		return fmt.Errorf("stat backup dir %s: %w", src, err)
	}
	return copyTree(src+"/.", dst+"/", "restore")
}

// copyTree shells out to `cp -a <src> <dst>`. The trailing `/.` on
// the source means "copy the source's contents into dst", not "copy
// the source directory itself into dst" — this is the cp(1) idiom
// for content-only copy that preserves the destination's directory
// identity.
//
// We shell out rather than walk the tree in Go because /var/lib
// carries symlinks, sockets, device nodes, and unusual permission
// bits that `cp -a` already handles correctly; reimplementing that
// would be a much bigger surface for bugs.
//
// op is "save" / "restore" — it ends up in log lines so the two call
// sites are distinguishable in journalctl.
//
// The destination is created at mode 0700 because /var/lib carries
// secrets (k3s tokens, kubeconfigs) and we don't want the backup
// root to be more permissive than the live tree.
func copyTree(src, dst, op string) error {
	log.Printf("state: %s tree %s -> %s", op, src, dst)
	if err := os.MkdirAll(dst, 0700); err != nil {
		return fmt.Errorf("%s: mkdir %s: %w", op, dst, err)
	}
	out, err := exec.Command("cp", "-a", src, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: cp -a %s %s: %w (output: %s)",
			op, src, dst, err, string(out))
	}
	log.Printf("state: %s tree %s -> %s done", op, src, dst)
	return nil
}
