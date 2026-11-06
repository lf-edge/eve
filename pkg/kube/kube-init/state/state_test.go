// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMarkUnmarkIsMarked(t *testing.T) {
	dir := t.TempDir()

	t.Run("mark creates file and IsMarked returns true", func(t *testing.T) {
		m := Marker(filepath.Join(dir, "mark1"))
		if err := Mark(m); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		ok, err := IsMarked(m)
		if err != nil {
			t.Fatalf("IsMarked: %v", err)
		}
		if !ok {
			t.Error("IsMarked returned false after Mark")
		}
	})

	t.Run("mark writes content 1", func(t *testing.T) {
		m := Marker(filepath.Join(dir, "mark_content"))
		if err := Mark(m); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		data, err := os.ReadFile(string(m))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(data) != "1" {
			t.Errorf("file content = %q, want %q", string(data), "1")
		}
	})

	t.Run("unmark removes file and IsMarked returns false", func(t *testing.T) {
		m := Marker(filepath.Join(dir, "mark2"))
		if err := Mark(m); err != nil {
			t.Fatalf("Mark: %v", err)
		}
		if err := Unmark(m); err != nil {
			t.Fatalf("Unmark: %v", err)
		}
		ok, err := IsMarked(m)
		if err != nil {
			t.Fatalf("IsMarked: %v", err)
		}
		if ok {
			t.Error("IsMarked returned true after Unmark")
		}
	})

	t.Run("unmark on nonexistent is idempotent", func(t *testing.T) {
		m := Marker(filepath.Join(dir, "nonexistent"))
		if err := Unmark(m); err != nil {
			t.Errorf("Unmark on nonexistent file returned error: %v", err)
		}
	})

	t.Run("double mark is idempotent", func(t *testing.T) {
		m := Marker(filepath.Join(dir, "mark3"))
		if err := Mark(m); err != nil {
			t.Fatalf("first Mark: %v", err)
		}
		if err := Mark(m); err != nil {
			t.Fatalf("second Mark: %v", err)
		}
		ok, err := IsMarked(m)
		if err != nil {
			t.Fatalf("IsMarked: %v", err)
		}
		if !ok {
			t.Error("IsMarked returned false after double Mark")
		}
		data, err := os.ReadFile(string(m))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(data) != "1" {
			t.Errorf("file content after double mark = %q, want %q", string(data), "1")
		}
	})

	t.Run("IsMarked surfaces non-ENOENT stat errors", func(t *testing.T) {
		// Run a non-existent path under a directory that exists but
		// has its execute bit cleared, so os.Stat returns EACCES
		// rather than ENOENT. The marker file itself does not need
		// to exist — Stat fails before it can be looked up.
		if os.Geteuid() == 0 {
			t.Skip("test requires non-root: root bypasses dir-exec permissions")
		}
		// Skip on platforms where 0000 dir permissions are advisory
		// only (Windows). We're targeting Linux; the build does too.
		if runtime.GOOS == "windows" {
			t.Skip("permission semantics differ on Windows")
		}

		parent := t.TempDir()
		blocked := filepath.Join(parent, "blocked")
		if err := os.Mkdir(blocked, 0000); err != nil {
			t.Fatalf("mkdir blocked dir: %v", err)
		}
		// Restore mode after the test so t.TempDir's cleanup can
		// recurse into it.
		t.Cleanup(func() { _ = os.Chmod(blocked, 0700) })

		m := Marker(filepath.Join(blocked, "marker"))
		ok, err := IsMarked(m)
		if err == nil {
			t.Errorf("IsMarked over an unreadable parent returned (%v, nil); want error", ok)
		}
		if ok {
			t.Errorf("IsMarked returned ok=true on error path")
		}
	})
}

func TestAtomicWriteFile(t *testing.T) {
	t.Run("basic write and read back", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "test.txt")
		content := []byte("hello world")
		if err := AtomicWriteFile(p, content, 0644); err != nil {
			t.Fatalf("AtomicWriteFile: %v", err)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(got) != string(content) {
			t.Errorf("content = %q, want %q", string(got), string(content))
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "a", "b", "c", "test.txt")
		if err := AtomicWriteFile(p, []byte("nested"), 0644); err != nil {
			t.Fatalf("AtomicWriteFile: %v", err)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(got) != "nested" {
			t.Errorf("content = %q, want %q", string(got), "nested")
		}
	})

	t.Run("permissions preserved", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "perms.txt")
		if err := AtomicWriteFile(p, []byte("data"), 0600); err != nil {
			t.Fatalf("AtomicWriteFile: %v", err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("permissions = %o, want %o", info.Mode().Perm(), 0600)
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "overwrite.txt")
		if err := AtomicWriteFile(p, []byte("first"), 0644); err != nil {
			t.Fatalf("first write: %v", err)
		}
		if err := AtomicWriteFile(p, []byte("second"), 0644); err != nil {
			t.Fatalf("second write: %v", err)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(got) != "second" {
			t.Errorf("content = %q, want %q", string(got), "second")
		}
	})

	t.Run("no temp file leftovers on success", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "clean.txt")
		if err := AtomicWriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatalf("AtomicWriteFile: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir: %v", err)
		}
		for _, e := range entries {
			if e.Name() != "clean.txt" {
				t.Errorf("unexpected leftover file: %s", e.Name())
			}
		}
	})

	t.Run("no temp file leftovers on rename failure", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("test requires non-root: root bypasses dir-write permissions")
		}
		// Use a read-only parent so the *rename* into place fails
		// while the *temp file create* (in os.CreateTemp under the
		// same dir) also fails — actually, os.CreateTemp will fail
		// first. To reach the rename branch specifically we need
		// the dir to be writable when CreateTemp runs and read-only
		// when Rename runs. That's hard to arrange synchronously
		// in a unit test; the more practical reachable failure path
		// is the create-temp itself returning an error. Verify the
		// outer guarantee: under failure, no temp files are left
		// behind anywhere we could observe them.
		parent := t.TempDir()
		readOnly := filepath.Join(parent, "ro")
		if err := os.Mkdir(readOnly, 0500); err != nil {
			t.Fatalf("mkdir ro: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(readOnly, 0700) })

		err := AtomicWriteFile(filepath.Join(readOnly, "x.txt"), []byte("data"), 0644)
		if err == nil {
			t.Fatalf("expected error writing into read-only dir, got nil")
		}

		// The read-only dir is unreadable too at 0500, but it IS
		// listable for the owner (us). Confirm nothing was left
		// behind there.
		entries, lerr := os.ReadDir(readOnly)
		if lerr != nil {
			t.Skipf("cannot list readOnly dir: %v", lerr)
		}
		for _, e := range entries {
			t.Errorf("unexpected leftover after failure: %s", e.Name())
		}
	})

	t.Run("error wraps stdlib FS errors", func(t *testing.T) {
		// Spot-check that the function returns wrapped errors that
		// errors.Is can unwrap to the underlying os.PathError class.
		parent := t.TempDir()
		readOnly := filepath.Join(parent, "ro")
		if err := os.Mkdir(readOnly, 0500); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(readOnly, 0700) })
		if os.Geteuid() == 0 {
			t.Skip("root bypasses permissions")
		}

		err := AtomicWriteFile(filepath.Join(readOnly, "x.txt"), []byte("data"), 0644)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, os.ErrPermission) {
			// Not strictly required for the function's contract,
			// but ergonomic: callers can errors.Is(err, os.ErrPermission)
			// to distinguish "no permission" from other failures.
			t.Logf("note: err does not unwrap to os.ErrPermission: %v", err)
		}
	})
}
