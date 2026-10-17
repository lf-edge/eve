// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher //nolint:testpackage // Internal tests need access to unexported helpers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeMemoryCgroup lays out <root>/memory/<cgroup> with the two files the
// kernel takes a memory pressure registration through.
func fakeMemoryCgroup(t *testing.T, root, cgroup string) string {
	t.Helper()
	dir := filepath.Join(root, "memory", cgroup)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"memory.pressure_level", "cgroup.event_control"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// zedbox collects garbage when the memory budget it lives under, /eve, comes
// under pressure anywhere below it. The registration goes through the host's
// cgroupfs, since pillar's own mount of it is read-only, and asks for medium
// pressure in hierarchy mode.
func TestRegisterMemoryPressure(t *testing.T) {
	root := t.TempDir()
	dir := fakeMemoryCgroup(t, root, "eve")

	fd, err := registerMemoryPressure(root, "/eve")
	if err != nil {
		t.Fatalf("registerMemoryPressure failed: %v", err)
	}
	defer func() { _ = fd.Close() }()
	registration, err := os.ReadFile(filepath.Join(dir, "cgroup.event_control"))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(registration))
	if len(fields) != 3 || fields[2] != "medium,hierarchy" {
		t.Fatalf("cgroup.event_control = %q, want \"<eventfd> <fd> medium,hierarchy\"", registration)
	}
}

// A registration that fails is reported, not a zero file descriptor that
// would be read as stdin.
func TestRegisterMemoryPressureWithoutCgroup(t *testing.T) {
	root := t.TempDir()

	fd, err := registerMemoryPressure(root, "/eve")
	if err == nil {
		t.Fatal("registerMemoryPressure succeeded without a memory cgroup")
	}
	if fd != nil {
		t.Fatalf("registerMemoryPressure returned a file (%v) with the error", fd.Name())
	}
}
