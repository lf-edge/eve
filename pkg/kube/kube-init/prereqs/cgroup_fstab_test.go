// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package prereqs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCgroupReplacesTheV1Entry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	orig := fstabPath
	fstabPath = path
	t.Cleanup(func() { fstabPath = orig })
	if err := os.WriteFile(path, []byte("proc /proc proc defaults 0 0\ncgroup /sys/fs/cgroup cgroup defaults 0 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second run must change nothing
		if err := SetupCgroup(); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	want := "proc /proc proc defaults 0 0\ncgroup2 /sys/fs/cgroup cgroup2 defaults 0 0\n"
	if string(b) != want {
		t.Errorf("fstab = %q, want %q", b, want)
	}
	if strings.Count(string(b), "/sys/fs/cgroup") != 1 {
		t.Error("exactly one /sys/fs/cgroup entry expected")
	}
}

// Lines other than the v1 entry, blank ones included, stay as they are.
func TestSetupCgroupKeepsTheOtherLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	orig := fstabPath
	fstabPath = path
	t.Cleanup(func() { fstabPath = orig })
	const others = "# static mounts\n\nproc /proc proc defaults 0 0\n\n"
	if err := os.WriteFile(path, []byte(others+"cgroup /sys/fs/cgroup cgroup defaults 0 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := SetupCgroup(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := others + "cgroup2 /sys/fs/cgroup cgroup2 defaults 0 0\n"
	if string(b) != want {
		t.Errorf("fstab = %q, want %q", b, want)
	}
}

func TestSetupCgroupCreatesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	orig := fstabPath
	fstabPath = path
	t.Cleanup(func() { fstabPath = orig })
	if err := SetupCgroup(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if want := "cgroup2 /sys/fs/cgroup cgroup2 defaults 0 0\n"; string(b) != want {
		t.Errorf("fstab = %q, want %q", b, want)
	}
}
