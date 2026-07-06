// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// procCorePattern is the kernel knob that names where process cores are written.
const procCorePattern = "/proc/sys/kernel/core_pattern"

// StagingDir is where the kernel drops raw qemu process cores before pillar
// correlates each to its domain, compresses it, and moves it into the domain's
// ring. It is a hidden subdir of the dump root so it never looks like a
// finished per-domain dump.
func StagingDir(dumpDir string) string {
	return filepath.Join(dumpDir, ".incoming")
}

// CorePattern is the absolute kernel core_pattern that writes raw qemu process
// cores into StagingDir, keyed by pid (%p) and time (%t) so FindCoreForPID can
// correlate a core to the domain whose qemu had that pid. It must be absolute
// so the kernel knows where to write regardless of the crashing process's CWD.
// No %e (comm): only qemu is given a non-zero RLIMIT_CORE, so every core here is
// already a qemu core.
func CorePattern(dumpDir string) string {
	return filepath.Join(StagingDir(dumpDir), "core-%p-%t")
}

// InstallCorePattern creates the staging directory and writes the core_pattern
// to procPath (pass procCorePattern in production, a temp file in tests). Call
// it only after the vault is mounted, since the staging dir lives in the vault.
func InstallCorePattern(procPath, dumpDir string) error {
	if err := os.MkdirAll(StagingDir(dumpDir), 0700); err != nil {
		return fmt.Errorf("qemudump: mkdir staging %s: %w", StagingDir(dumpDir), err)
	}
	if err := os.WriteFile(procPath, []byte(CorePattern(dumpDir)), 0644); err != nil {
		return fmt.Errorf("qemudump: write core_pattern %s: %w", procPath, err)
	}
	return nil
}

// InstallDefaultCorePattern installs the core_pattern at the real kernel path.
func InstallDefaultCorePattern(dumpDir string) error {
	return InstallCorePattern(procCorePattern, dumpDir)
}

// SweepStaging removes any raw cores left in the staging dir. Call it once at
// pillar startup: anything there is an orphan from a previous boot (its qemu
// pid is gone, so it can't be attributed to a domain and would otherwise linger
// unbounded). Files are only picked up promptly when a live domain dies, so a
// startup sweep cannot race an in-progress capture. A missing dir is not an
// error.
func (m *Manager) SweepStaging() error {
	staging := StagingDir(m.cfg.Dir)
	entries, err := os.ReadDir(staging)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("qemudump: readdir staging %s: %w", staging, err)
	}
	var firstErr error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(staging, e.Name())); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("qemudump: sweep %s: %w", e.Name(), err)
		}
	}
	return firstErr
}

// SweepStagingStale removes raw cores in the staging dir whose mtime is older
// than maxAge. Unlike SweepStaging (boot-only, removes everything) this is safe
// to call at runtime: a real core is picked up promptly when its domain dies, so
// anything older than maxAge is an orphan — qemu pid already gone, a failed
// pickup, or (core_pattern is host-global) a core from a non-qemu process — that
// would otherwise linger unbounded until the next reboot. A missing dir is not
// an error.
func (m *Manager) SweepStagingStale(maxAge time.Duration) error {
	staging := StagingDir(m.cfg.Dir)
	entries, err := os.ReadDir(staging)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("qemudump: readdir staging %s: %w", staging, err)
	}
	cutoff := time.Now().Add(-maxAge)
	var firstErr error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // vanished between ReadDir and Info; skip
		}
		if info.ModTime().After(cutoff) {
			continue // too recent: may be in-progress or awaiting prompt pickup
		}
		if err := os.Remove(filepath.Join(staging, e.Name())); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("qemudump: sweep stale %s: %w", e.Name(), err)
		}
	}
	return firstErr
}

// FindCoreForPID returns the path of a raw core in the staging dir written for
// pid, or "" if none. The core_pattern names files core-<pid>-<time>.
func FindCoreForPID(dumpDir string, pid int) (string, error) {
	matches, err := filepath.Glob(filepath.Join(StagingDir(dumpDir), "core-"+strconv.Itoa(pid)+"-*"))
	if err != nil {
		return "", fmt.Errorf("qemudump: glob core for pid %d: %w", pid, err)
	}
	if len(matches) == 0 {
		return "", nil
	}
	return matches[0], nil
}
