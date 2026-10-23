// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package prereqs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countCPUList feeds the Apply concurrency cap, so a misparse silently
// changes how much work a first boot runs at once.
func TestCountCPUList(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0", 1},
		{"0-7", 8},
		{"0-0", 1},
		{"0,2-4", 4},
		{"0,1,2", 3},
		{"2-4,8,10-11", 6},
		{"", 0},
		{"garbage", 0},
		{"4-2", 0},   // reversed range contributes nothing
		{"0-3,x", 4}, // malformed segment skipped, valid one kept
	}
	for _, c := range cases {
		if got := countCPUList(c.in); got != c.want {
			t.Errorf("countCPUList(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Restore must tolerate the nil loan WidenKubeCPUs returns when there is
// nothing to widen, since the FSM calls it unconditionally.
func TestCPUSetLoanRestoreIsSafeWhenNil(t *testing.T) {
	var loan *CPUSetLoan
	loan.Restore()
	loan.Restore()

	empty := &CPUSetLoan{saved: map[string]string{}}
	empty.Restore()
}

// fakeCPUSetTree builds a cgroup-v2-shaped tree under a temp dir and points
// cpusetRoot at it: the root offers "0-7" (cpuset.cpus.effective); the given
// groups start with cpuset.cpus = mask ("" = inherits, as per-service leaves
// do on v2).
func fakeCPUSetTree(t *testing.T, groups map[string]string) string {
	t.Helper()
	root := t.TempDir()
	orig := cpusetRoot
	cpusetRoot = root
	t.Cleanup(func() { cpusetRoot = orig })
	if err := os.WriteFile(filepath.Join(root, "cpuset.cpus.effective"), []byte("0-7\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for cg, mask := range groups {
		if err := os.MkdirAll(filepath.Join(root, cg), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, cg, "cpuset.cpus"), []byte(mask+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readMask(t *testing.T, root, cg string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, cg, "cpuset.cpus"))
	if err != nil {
		t.Fatalf("read %s: %v", cg, err)
	}
	return strings.TrimSpace(string(b))
}

// 010-eve-cgroup confines /eve, /eve/services and /eve/containerd; the
// service leaves inherit. Widening must open the three and leave the
// inheriting leaves alone, and Restore must put the three back.
func TestWidenEVECPUsCoversConfinedGroupsAndRestores(t *testing.T) {
	root := fakeCPUSetTree(t, map[string]string{
		"eve": "0", "eve/services": "0", "eve/containerd": "0",
		"eve/services/kube": "", "eve/services/pillar": "",
	})
	loan := WidenEVECPUs()
	if loan == nil {
		t.Fatal("WidenEVECPUs returned nil on a confined tree")
	}
	for _, cg := range []string{"eve", "eve/services", "eve/containerd"} {
		if got := readMask(t, root, cg); got != "0-7" {
			t.Errorf("%s = %q after widen, want \"0-7\"", cg, got)
		}
	}
	for _, cg := range []string{"eve/services/kube", "eve/services/pillar"} {
		if got := readMask(t, root, cg); got != "" {
			t.Errorf("%s = %q, want \"\" (inherits)", cg, got)
		}
	}
	loan.Restore()
	for _, cg := range []string{"eve", "eve/services", "eve/containerd"} {
		if got := readMask(t, root, cg); got != "0" {
			t.Errorf("%s = %q after restore, want \"0\"", cg, got)
		}
	}
}

// A leaf with a mask of its own is widened and restored like the groups.
func TestWidenEVECPUsWidensAnExplicitLeaf(t *testing.T) {
	root := fakeCPUSetTree(t, map[string]string{"eve": "0", "eve/services": "0", "eve/services/kube": "0"})
	loan := WidenEVECPUs()
	if loan == nil {
		t.Fatal("WidenEVECPUs returned nil")
	}
	if got := readMask(t, root, "eve/services/kube"); got != "0-7" {
		t.Errorf("kube = %q after widen, want \"0-7\"", got)
	}
	loan.Restore()
	if got := readMask(t, root, "eve/services/kube"); got != "0" {
		t.Errorf("kube = %q after restore, want \"0\"", got)
	}
}

// kube's own cpuset.cpus is empty on v2 (it inherits): its CPU count comes
// from cpuset.cpus.effective.
func TestKubeCPUCountReadsEffective(t *testing.T) {
	root := fakeCPUSetTree(t, map[string]string{"eve/services/kube": ""})
	if err := os.WriteFile(filepath.Join(root, "eve/services/kube/cpuset.cpus.effective"), []byte("0-3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := KubeCPUCount(); got != 4 {
		t.Errorf("KubeCPUCount() = %d, want 4", got)
	}
}

// One unreadable leaf must not abandon its siblings — each is independent
// once the ancestors are open.
func TestWidenEVECPUsSkipsBadLeafButKeepsSiblings(t *testing.T) {
	root := fakeCPUSetTree(t, map[string]string{"eve": "0", "eve/services": "0", "eve/services/kube": "0", "eve/services/broken": "0"})
	// A directory where cpuset.cpus should be makes the leaf unreadable.
	bad := filepath.Join(root, "eve/services/broken", "cpuset.cpus")
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bad, 0755); err != nil {
		t.Fatal(err)
	}

	loan := WidenEVECPUs()
	if loan == nil {
		t.Fatal("a single bad leaf must not abandon the whole widen")
	}
	t.Cleanup(loan.Restore)
	if got := readMask(t, root, "eve/services/kube"); got != "0-7" {
		t.Errorf("healthy sibling = %q, want \"0-7\"", got)
	}
}

// An unwidenable ancestor aborts: a leaf widened under an un-widened
// parent would take effect only once the parent opens.
func TestWidenEVECPUsAbortsOnBadAncestor(t *testing.T) {
	root := fakeCPUSetTree(t, map[string]string{"eve": "0", "eve/services": "0", "eve/services/kube": "0"})
	bad := filepath.Join(root, "eve", "cpuset.cpus")
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bad, 0755); err != nil {
		t.Fatal(err)
	}

	if loan := WidenEVECPUs(); loan != nil {
		loan.Restore()
		t.Fatal("expected nil loan when an ancestor cannot be widened")
	}
	if got := readMask(t, root, "eve/services/kube"); got != "0" {
		t.Errorf("leaf = %q, want untouched \"0\" after ancestor failure", got)
	}
}
