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
// transition. /var/lib is tmpfs on EVE, so without this backup a
// failed transition would lose all kube state.
const KubeSaveVarLib = "/persist/kube-save-var-lib"

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
