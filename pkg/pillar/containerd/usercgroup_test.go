// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// daemonPid is the pid of the user containerd daemon in the fake /proc.
const daemonPid = 4242

// fakeProcCgroup writes <procRoot>/<daemonPid>/cgroup as the kernel shows it
// under cgroup v1, with the daemon in memoryCgroup for the memory controller.
func fakeProcCgroup(t *testing.T, procRoot string, memoryCgroup string) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(daemonPid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "12:cpuset:/eve/containerd\n9:memory:" + memoryCgroup + "\n1:name=systemd:/\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func memoryHierarchy(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

// The user containerd daemon is charged to the containerd cgroup beside the
// domains once it has joined the cgroup its configuration names.
func TestJoinUserContainerdCgroup(t *testing.T) {
	root := memoryHierarchy(t)
	procRoot := t.TempDir()
	fakeProcCgroup(t, procRoot, ctrdConfiguredCgroup)

	if err := joinUserContainerdCgroup(root, procRoot, daemonPid, time.Second); err != nil {
		t.Fatalf("joinUserContainerdCgroup failed: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(root, "eve-user-apps", "containerd", "cgroup.procs"))
	if err != nil {
		t.Fatalf("the containerd cgroup was not populated: %v", err)
	}
	if string(procs) != strconv.Itoa(daemonPid) {
		t.Fatalf("cgroup.procs = %q, want the daemon's pid", procs)
	}
}

// The daemon joins its configured cgroup on its own shortly after it starts,
// which would undo an earlier move, so the move waits for that to happen.
func TestJoinUserContainerdCgroupWaitsForTheDaemon(t *testing.T) {
	root := memoryHierarchy(t)
	procRoot := t.TempDir()
	fakeProcCgroup(t, procRoot, "/eve/services/pillar")
	go func() {
		time.Sleep(100 * time.Millisecond)
		fakeProcCgroup(t, procRoot, ctrdConfiguredCgroup)
	}()

	if err := joinUserContainerdCgroup(root, procRoot, daemonPid, 5*time.Second); err != nil {
		t.Fatalf("joinUserContainerdCgroup failed: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(root, "eve-user-apps", "containerd", "cgroup.procs"))
	if err != nil {
		t.Fatalf("the containerd cgroup was not populated: %v", err)
	}
	if string(procs) != strconv.Itoa(daemonPid) {
		t.Fatalf("cgroup.procs = %q, want the daemon's pid", procs)
	}
}

// A daemon that never shows up in its configured cgroup is left alone, with
// an error for the caller.
func TestJoinUserContainerdCgroupGivesUp(t *testing.T) {
	root := memoryHierarchy(t)
	procRoot := t.TempDir()
	fakeProcCgroup(t, procRoot, "/eve/services/pillar")

	if err := joinUserContainerdCgroup(root, procRoot, daemonPid, 100*time.Millisecond); err == nil {
		t.Fatal("joinUserContainerdCgroup succeeded although the daemon never joined its cgroup")
	}
	if _, err := os.Stat(filepath.Join(root, "eve-user-apps", "containerd", "cgroup.procs")); !os.IsNotExist(err) {
		t.Fatalf("the daemon was moved anyway: %v", err)
	}
}

// Without a cgroup v1 memory hierarchy there is nothing to move to.
func TestJoinUserContainerdCgroupWithoutMemoryHierarchy(t *testing.T) {
	root := t.TempDir()
	procRoot := t.TempDir()
	fakeProcCgroup(t, procRoot, ctrdConfiguredCgroup)

	err := joinUserContainerdCgroup(root, procRoot, daemonPid, time.Second)
	if !errors.Is(err, ErrNoMemoryHierarchy) {
		t.Fatalf("joinUserContainerdCgroup returned %v, want ErrNoMemoryHierarchy", err)
	}
	if _, err := os.Stat(filepath.Join(root, "eve-user-apps")); !os.IsNotExist(err) {
		t.Fatalf("a cgroup was created without a memory hierarchy: %v", err)
	}
}
