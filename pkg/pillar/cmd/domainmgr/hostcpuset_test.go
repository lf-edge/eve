// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
)

const (
	userFlags    = 0x00400100 // a user-space process
	kthreadFlags = 0x00208040 // PF_KTHREAD set
)

// fakeHostCpuset builds a cgroup v2 root that enables cpuset for its children
// and holds rootProcs, and a procfs with a stat file per entry of procs (pid ->
// flags). The housekeeping group's files exist and are empty, as cgroupfs
// creates them on mkdir.
func fakeHostCpuset(t *testing.T, rootProcs []int, procs map[int]uint64) (*hostCpuset, string) {
	t.Helper()
	var list []string
	for _, pid := range rootProcs {
		list = append(list, fmt.Sprint(pid))
	}
	root := cgrouptest.FakeTree(t, map[string]string{
		"cgroup.subtree_control":          "cpuset cpu io memory pids\n",
		"cgroup.procs":                    strings.Join(list, "\n") + "\n",
		hostCpusetGroup + "/cpuset.cpus":  "",
		hostCpusetGroup + "/cgroup.procs": "",
	})
	proc := t.TempDir()
	for pid, flags := range procs {
		// A comm with a space and a parenthesis: the fields must be counted
		// from the last ')'.
		writeTestFile(t, filepath.Join(proc, fmt.Sprint(pid), "stat"),
			fmt.Sprintf("%d (a) b) S 1 1 1 0 -1 %d 0 0 0 0\n", pid, flags))
	}
	h, err := newHostCpuset(proc)
	if err != nil {
		t.Fatal(err)
	}
	return h, filepath.Join(root, hostCpusetGroup)
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// The group gets the CPUs, and only user-space processes are moved into it --
// kernel threads, and processes that exited meanwhile, are not.
func TestHostCpuset_MovesUserSpaceProcessesOnly(t *testing.T) {
	h, dir := fakeHostCpuset(t, []int{1, 2, 552, 777},
		map[int]uint64{1: userFlags, 2: kthreadFlags, 552: userFlags})
	moved, err := h.apply([]uint32{0, 27})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if moved != 2 {
		t.Errorf("moved %d processes, want 2 (pid 1 and 552)", moved)
	}
	if got := readTestFile(t, filepath.Join(dir, "cpuset.cpus")); got != "0,27" {
		t.Errorf("cpuset.cpus = %q, want 0,27", got)
	}
}

// Where the root does not hand cpuset to its children, a group of its own would
// not confine the host processes, so there is no host cpuset.
func TestNewHostCpuset_NeedsCpusetForChildren(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"cgroup.subtree_control": "cpu io memory pids\n"})
	if h, err := newHostCpuset(t.TempDir()); err == nil || h != nil {
		t.Errorf("newHostCpuset = %v, %v; want an error", h, err)
	}
}

// An empty cpuset cannot hold a process, so an empty set is refused outright
// rather than written and then failing on every move.
func TestHostCpuset_EmptySetIsRefused(t *testing.T) {
	h, dir := fakeHostCpuset(t, []int{1}, map[int]uint64{1: userFlags})
	if _, err := h.apply(nil); err == nil {
		t.Error("an empty CPU set must be refused")
	}
	if got := readTestFile(t, filepath.Join(dir, "cpuset.cpus")); got != "" {
		t.Errorf("nothing may be written for an empty set, got cpus %q", got)
	}
}

// A process that cannot be moved does not stop the others from being moved.
func TestHostCpuset_AFailedMoveIsNotFatal(t *testing.T) {
	h, dir := fakeHostCpuset(t, []int{1}, map[int]uint64{1: userFlags})
	// A directory where cgroup.procs should be makes every move fail.
	procs := filepath.Join(dir, "cgroup.procs")
	if err := os.Remove(procs); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(procs, 0755); err != nil {
		t.Fatal(err)
	}
	moved, err := h.apply([]uint32{0})
	if err != nil || moved != 0 {
		t.Errorf("moved %d, err %v; want nothing moved and no error", moved, err)
	}
}

// The contexts built by tests and tools have no host cpuset, and must not touch
// the machine's cgroups.
func TestHostCpuset_NilIsANoOp(t *testing.T) {
	var h *hostCpuset
	if moved, err := h.apply([]uint32{0}); moved != 0 || err != nil {
		t.Errorf("a nil host cpuset must do nothing, got %d, %v", moved, err)
	}
}

// The host processes follow the allocator: once a workload holds CPUs, the pool
// update narrows the host cpuset to the housekeeping CPUs that are left.
func TestPublishCPUPoolStatus_NarrowsHostCpuset(t *testing.T) {
	h, dir := fakeHostCpuset(t, nil, nil)
	ctx := placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(testPlacer(t)), hostCpuset: h})
	if err := ctx.cpuPlacement.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "pinned"), []uint32{1, 5}); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	ctx.cpuPlacement.publish(ctx)

	if got := readTestFile(t, filepath.Join(dir, "cpuset.cpus")); got != "0,2,3,4,6,7" {
		t.Errorf("cpuset.cpus = %q, want the housekeeping CPUs 0,2,3,4,6,7", got)
	}
}
