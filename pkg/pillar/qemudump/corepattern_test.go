// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"os"
	"path/filepath"
	"testing"
)

// The core_pattern points the kernel at an absolute staging path under the dump
// dir, keyed by pid and time so a per-domain pickup can correlate it later.
func TestCorePatternAndStagingDir(t *testing.T) {
	dir := "/persist/vault/qemu-trace"
	if got, want := StagingDir(dir), "/persist/vault/qemu-trace/.incoming"; got != want {
		t.Fatalf("StagingDir = %q, want %q", got, want)
	}
	want := "/persist/vault/qemu-trace/.incoming/core-%p-%t"
	if got := CorePattern(dir); got != want {
		t.Fatalf("CorePattern = %q, want %q", got, want)
	}
	if CorePattern(dir)[0] != '/' {
		t.Fatalf("core_pattern must be absolute so the kernel knows where to write")
	}
}

// InstallCorePattern creates the staging dir and writes the pattern to the
// (injected) kernel core_pattern path.
func TestInstallCorePattern(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "qemu-trace")
	procPath := filepath.Join(root, "core_pattern")

	if err := InstallCorePattern(procPath, dir); err != nil {
		t.Fatalf("InstallCorePattern: %v", err)
	}
	got, err := os.ReadFile(procPath)
	if err != nil {
		t.Fatalf("read core_pattern: %v", err)
	}
	if string(got) != CorePattern(dir) {
		t.Fatalf("core_pattern file = %q, want %q", got, CorePattern(dir))
	}
	if fi, err := os.Stat(StagingDir(dir)); err != nil || !fi.IsDir() {
		t.Fatalf("staging dir not created: %v", err)
	}
}

// FindCoreForPID locates a raw core belonging to a given pid and ignores cores
// of other pids.
func TestFindCoreForPID(t *testing.T) {
	dir := t.TempDir()
	staging := StagingDir(dir)
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	want := filepath.Join(staging, "core-12345-1720000000")
	for _, name := range []string{"core-999-1720000001", "core-12345-1720000000", "core-42-1720000002"} {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("x"), 0600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	got, err := FindCoreForPID(dir, 12345)
	if err != nil {
		t.Fatalf("FindCoreForPID: %v", err)
	}
	if got != want {
		t.Fatalf("FindCoreForPID = %q, want %q", got, want)
	}

	if got, _ := FindCoreForPID(dir, 7777); got != "" {
		t.Fatalf("FindCoreForPID for absent pid = %q, want empty", got)
	}
}

// SweepStaging removes orphaned raw cores (from a previous boot, pid gone) but
// leaves subdirectories and a missing dir alone.
func TestSweepStaging(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(Config{Dir: dir})
	staging := StagingDir(dir)
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, n := range []string{"core-111-1720000000", "core-222-1720000001"} {
		if err := os.WriteFile(filepath.Join(staging, n), []byte("x"), 0600); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if err := m.SweepStaging(); err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}
	ents, _ := os.ReadDir(staging)
	if len(ents) != 0 {
		t.Fatalf("orphans not swept: %v", ents)
	}

	// Missing staging dir is not an error.
	if err := NewManager(Config{Dir: filepath.Join(dir, "gone")}).SweepStaging(); err != nil {
		t.Fatalf("SweepStaging on missing dir: %v", err)
	}
}
