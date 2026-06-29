// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCopyTreeRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("cp"); err != nil {
		t.Skipf("cp not on PATH: %v", err)
	}

	srcRoot := t.TempDir()
	dstRoot := t.TempDir()

	if err := os.MkdirAll(filepath.Join(srcRoot, "a/b"), 0755); err != nil {
		t.Fatalf("mkdir src tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "a/b/file.txt"),
		[]byte("payload"), 0640); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
	if err := os.Symlink("b/file.txt", filepath.Join(srcRoot, "a/link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := copyTree(srcRoot+"/.", dstRoot+"/", "test"); err != nil {
		t.Fatalf("copyTree: %v", err)
	}

	// File content preserved.
	got, err := os.ReadFile(filepath.Join(dstRoot, "a/b/file.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("copied file content = %q, want %q", string(got), "payload")
	}

	// Permission bits preserved (cp -a).
	info, err := os.Stat(filepath.Join(dstRoot, "a/b/file.txt"))
	if err != nil {
		t.Fatalf("stat copied file: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("copied file perm = %o, want 0640", info.Mode().Perm())
	}

	// Symlink preserved as a symlink AND its target string survived.
	linkPath := filepath.Join(dstRoot, "a/link")
	li, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat copied symlink: %v", err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was not preserved as a symlink: mode=%v", li.Mode())
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "b/file.txt" {
		t.Errorf("symlink target = %q, want %q", target, "b/file.txt")
	}
}

func TestCopyTreeMissingSource(t *testing.T) {
	if _, err := exec.LookPath("cp"); err != nil {
		t.Skipf("cp not on PATH: %v", err)
	}
	dst := t.TempDir()
	err := copyTree("/nonexistent/path/.", dst+"/", "test")
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
}

func TestCopyTreeMkdirFailure(t *testing.T) {
	// dst is *under* an existing regular file — MkdirAll must fail.
	parent := t.TempDir()
	regular := filepath.Join(parent, "regular-file")
	if err := os.WriteFile(regular, []byte("x"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	dst := filepath.Join(regular, "child", "dst")
	err := copyTree("/tmp/.", dst+"/", "test")
	if err == nil {
		t.Fatal("expected mkdir error when parent is a regular file, got nil")
	}
}

func TestSaveAndRestoreRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("cp"); err != nil {
		t.Skipf("cp not on PATH: %v", err)
	}
	varLib := t.TempDir()
	backupParent := t.TempDir()
	backup := filepath.Join(backupParent, "kube-save-var-lib")
	restored := t.TempDir()

	if err := os.MkdirAll(filepath.Join(varLib, "rancher/k3s"), 0755); err != nil {
		t.Fatalf("seed varLib: %v", err)
	}
	if err := os.WriteFile(filepath.Join(varLib, "rancher/k3s/server-token"),
		[]byte("topsecret"), 0600); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := saveVarLibTo(varLib, backup); err != nil {
		t.Fatalf("saveVarLibTo: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(backup, "rancher/k3s/server-token"))
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(got) != "topsecret" {
		t.Errorf("backup content = %q, want %q", string(got), "topsecret")
	}

	// Staging dir must NOT linger after a successful save.
	if _, err := os.Stat(backup + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected staging dir to be gone, stat err = %v", err)
	}

	if err := restoreVarLibFrom(backup, restored); err != nil {
		t.Fatalf("restoreVarLibFrom: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(restored, "rancher/k3s/server-token"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "topsecret" {
		t.Errorf("restored content = %q, want %q", string(got), "topsecret")
	}
}

func TestSaveReplacesPriorBackupAtomically(t *testing.T) {
	if _, err := exec.LookPath("cp"); err != nil {
		t.Skipf("cp not on PATH: %v", err)
	}
	varLib := t.TempDir()
	backup := filepath.Join(t.TempDir(), "kube-save-var-lib")

	// Stage 1: save with one payload.
	if err := os.WriteFile(filepath.Join(varLib, "f"), []byte("v1"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := saveVarLibTo(varLib, backup); err != nil {
		t.Fatalf("first saveVarLibTo: %v", err)
	}

	// Stage 2: change payload + leave a stale extra file in the
	// previous backup that must NOT survive the second save.
	if err := os.WriteFile(filepath.Join(backup, "stale"), []byte("old"), 0600); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	if err := os.WriteFile(filepath.Join(varLib, "f"), []byte("v2"), 0600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := saveVarLibTo(varLib, backup); err != nil {
		t.Fatalf("second saveVarLibTo: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(backup, "f"))
	if err != nil {
		t.Fatalf("read backup f: %v", err)
	}
	if string(got) != "v2" {
		t.Errorf("backup f = %q, want %q (second save did not replace contents)",
			string(got), "v2")
	}
	if _, err := os.Stat(filepath.Join(backup, "stale")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale file from prior backup survived: stat err = %v", err)
	}
}

func TestSaveSourceMissingWrapsNotFound(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "kube-save-var-lib")
	err := saveVarLibTo("/nonexistent/"+t.Name(), backup)
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist in chain, got %v", err)
	}
	// The backup dir must NOT have been created when the source is
	// missing — otherwise a future RestoreVarLib would silently apply
	// an empty backup to /var/lib.
	if _, statErr := os.Stat(backup); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("backup dir was created despite missing source: stat err = %v", statErr)
	}
}

func TestRestoreMissingBackupWrapsNotFound(t *testing.T) {
	err := restoreVarLibFrom("/nonexistent/path/"+t.Name(), t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing backup, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist in chain, got %v", err)
	}
}

func TestRestoreBackupStatPermissionError(t *testing.T) {
	// A permission-denied stat must NOT be misclassified as
	// os.ErrNotExist — callers rely on that distinction to decide
	// "nothing to restore" vs "broken backup".
	if os.Geteuid() == 0 {
		t.Skip("root bypasses dir-exec permissions")
	}
	parent := t.TempDir()
	blocked := filepath.Join(parent, "blocked")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0700); err != nil {
			t.Logf("chmod restore: %v", err)
		}
	})

	err := restoreVarLibFrom(filepath.Join(blocked, "backup"), t.TempDir())
	if err == nil {
		t.Fatal("expected stat error, got nil")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("permission error misclassified as os.ErrNotExist: %v", err)
	}
}
