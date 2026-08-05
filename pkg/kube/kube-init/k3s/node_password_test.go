// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"os"
	"path/filepath"
	"testing"
)

// redirectNodePasswdPaths points the package-level path vars at
// t.TempDir() so each test gets an isolated fs view. Restored via
// t.Cleanup.
func redirectNodePasswdPaths(t *testing.T) (persist, runtime, stale string) {
	t.Helper()
	dir := t.TempDir()
	persist = filepath.Join(dir, "persist")
	runtime = filepath.Join(dir, "runtime")
	stale = filepath.Join(dir, "stale-flag")
	oldP, oldR, oldS := PersistNodePasswdFile, RuntimeNodePasswdFile, StaleNodePasswdFlag
	PersistNodePasswdFile = persist
	RuntimeNodePasswdFile = runtime
	StaleNodePasswdFlag = stale
	t.Cleanup(func() {
		PersistNodePasswdFile, RuntimeNodePasswdFile, StaleNodePasswdFlag = oldP, oldR, oldS
	})
	return
}

func TestRestoreNodePassword_NoPersistFile(t *testing.T) {
	_, runtime, _ := redirectNodePasswdPaths(t)
	if err := RestoreNodePassword(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(runtime); !os.IsNotExist(err) {
		t.Errorf("runtime file should not exist on a fresh device, got %v", err)
	}
}

func TestRestoreNodePassword_CopiesAndChmods(t *testing.T) {
	persist, runtime, _ := redirectNodePasswdPaths(t)
	want := []byte("hunter2\n")
	if err := os.WriteFile(persist, want, 0o600); err != nil {
		t.Fatalf("seed persist: %v", err)
	}

	if err := RestoreNodePassword(); err != nil {
		t.Fatalf("RestoreNodePassword: %v", err)
	}

	got, err := os.ReadFile(runtime)
	if err != nil {
		t.Fatalf("read runtime: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
	info, err := os.Stat(runtime)
	if err != nil {
		t.Fatalf("stat runtime: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("runtime perm = %#o, want 0600", perm)
	}
}

func TestSaveNodePassword_NoRuntime(t *testing.T) {
	persist, _, stale := redirectNodePasswdPaths(t)
	if err := SaveNodePassword(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range []string{persist, stale} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should not exist when runtime is missing, got %v", p, err)
		}
	}
}

func TestSaveNodePassword_PersistMissing_TouchesStale(t *testing.T) {
	persist, runtime, stale := redirectNodePasswdPaths(t)
	want := []byte("freshly-generated-password\n")
	if err := os.WriteFile(runtime, want, 0o600); err != nil {
		t.Fatalf("seed runtime: %v", err)
	}

	if err := SaveNodePassword(); err != nil {
		t.Fatalf("SaveNodePassword: %v", err)
	}

	got, err := os.ReadFile(persist)
	if err != nil {
		t.Fatalf("read persist: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("persist contents = %q, want %q", got, want)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Errorf("brownfield first boot must touch stale flag at %s, got %v", stale, err)
	}
}

func TestSaveNodePassword_PersistMatches_NoOp(t *testing.T) {
	persist, runtime, stale := redirectNodePasswdPaths(t)
	body := []byte("steady-state-password\n")
	if err := os.WriteFile(runtime, body, 0o600); err != nil {
		t.Fatalf("seed runtime: %v", err)
	}
	if err := os.WriteFile(persist, body, 0o600); err != nil {
		t.Fatalf("seed persist: %v", err)
	}

	if err := SaveNodePassword(); err != nil {
		t.Fatalf("SaveNodePassword: %v", err)
	}

	// Stale flag must NOT have been touched — equal contents means
	// we're past the brownfield case.
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale flag should not be set when persist matches runtime, got %v", err)
	}
}

func TestSaveNodePassword_PersistDiffers_OverwritesNoStale(t *testing.T) {
	persist, runtime, stale := redirectNodePasswdPaths(t)
	newRuntime := []byte("rotated-password\n")
	if err := os.WriteFile(runtime, newRuntime, 0o600); err != nil {
		t.Fatalf("seed runtime: %v", err)
	}
	if err := os.WriteFile(persist, []byte("older-password\n"), 0o600); err != nil {
		t.Fatalf("seed persist: %v", err)
	}

	if err := SaveNodePassword(); err != nil {
		t.Fatalf("SaveNodePassword: %v", err)
	}

	got, err := os.ReadFile(persist)
	if err != nil {
		t.Fatalf("read persist: %v", err)
	}
	if string(got) != string(newRuntime) {
		t.Errorf("persist contents = %q, want %q", got, newRuntime)
	}
	// Differing but present persist file means this is NOT the
	// brownfield case — stale flag must not be created.
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale flag should not be set when persist already existed, got %v", err)
	}
}

func TestSaveNodePassword_PersistPermission(t *testing.T) {
	persist, runtime, _ := redirectNodePasswdPaths(t)
	if err := os.WriteFile(runtime, []byte("p\n"), 0o600); err != nil {
		t.Fatalf("seed runtime: %v", err)
	}
	if err := SaveNodePassword(); err != nil {
		t.Fatalf("SaveNodePassword: %v", err)
	}
	info, err := os.Stat(persist)
	if err != nil {
		t.Fatalf("stat persist: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("persist perm = %#o, want 0600", perm)
	}
}
