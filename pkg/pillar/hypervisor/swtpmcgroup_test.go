// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// fakeProc writes a /proc-like tree in which each pid has the given command
// line, as a swtpm started by vtpm for the domain would show it.
func fakeProc(t *testing.T, procs map[int][]string) string {
	t.Helper()
	procRoot := t.TempDir()
	for pid, args := range procs {
		dir := filepath.Join(procRoot, fmt.Sprint(pid))
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		cmdline := strings.Join(args, "\x00") + "\x00"
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return procRoot
}

func swtpmArgs(id uuid.UUID) []string {
	return []string{"swtpm", "socket", "--tpm2",
		"--ctrl", "type=unixio,path=" + fmt.Sprintf(types.SwtpmCtrlSocketPath, id),
		"--pid", "file=" + fmt.Sprintf(types.SwtpmPidPath, id)}
}

// A domain's swtpm is per-domain overhead like its shim, so once vtpm has
// launched it, it must move from vtpm's service cgroup under /eve to the
// helpers child of the domain's own cgroup, in the memory hierarchy, created
// ahead of the task. vtpm runs in its own pid namespace, so the pid it records
// is of no use to pillar: the swtpm is found by the pid file named on its
// command line.
func TestJoinSwtpmCgroup(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	id := uuid.Must(uuid.NewV4())
	other := uuid.Must(uuid.NewV4())
	procRoot := fakeProc(t, map[int][]string{
		1:    {"/sbin/init"},
		4242: swtpmArgs(id),
		4243: swtpmArgs(other),
		4244: {"grep", fmt.Sprintf(types.SwtpmPidPath, id)},
	})

	if err := joinSwtpmCgroup(root, procRoot, id, "task-1"); err != nil {
		t.Fatalf("joinSwtpmCgroup failed: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(root, "eve-user-apps", "task-1", "helpers", "cgroup.procs"))
	if err != nil {
		t.Fatalf("the helpers cgroup was not populated: %v", err)
	}
	if string(procs) != "4242" {
		t.Fatalf("cgroup.procs = %q, want the pid 4242 of the domain's swtpm", procs)
	}
}

// Without a cgroup v1 memory hierarchy the swtpm stays in vtpm's cgroup, and
// nothing is created where that hierarchy would be mounted.
func TestJoinSwtpmCgroupWithoutMemoryHierarchy(t *testing.T) {
	root := t.TempDir()
	id := uuid.Must(uuid.NewV4())
	procRoot := fakeProc(t, map[int][]string{4242: swtpmArgs(id)})

	err := joinSwtpmCgroup(root, procRoot, id, "task-1")
	if !errors.Is(err, containerd.ErrNoMemoryHierarchy) {
		t.Fatalf("joinSwtpmCgroup returned %v, want ErrNoMemoryHierarchy", err)
	}
	if _, err := os.Stat(filepath.Join(root, "eve-user-apps")); !os.IsNotExist(err) {
		t.Fatalf("a cgroup was created without a memory hierarchy: %v", err)
	}
}

// A domain without a running swtpm is an error, so the caller can report it.
func TestJoinSwtpmCgroupWithoutProcess(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"), []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	procRoot := fakeProc(t, map[int][]string{4243: swtpmArgs(uuid.Must(uuid.NewV4()))})

	if err := joinSwtpmCgroup(root, procRoot, uuid.Must(uuid.NewV4()), "task-1"); err == nil {
		t.Fatal("joinSwtpmCgroup succeeded without a swtpm process for the domain")
	}
}
