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

// fakeCPUSetTree builds a cgroup-v1-shaped cpuset tree under a temp dir
// and points cpusetRoot at it. Every group starts confined to "0", the
// host mask is "0-7", mirroring an EVE device with eve_max_vcpus=1.
func fakeCPUSetTree(t *testing.T, leaves ...string) string {
	t.Helper()
	root := t.TempDir()
	orig := cpusetRoot
	cpusetRoot = root
	t.Cleanup(func() { cpusetRoot = orig })

	if err := os.WriteFile(filepath.Join(root, "cpuset.cpus"), []byte("0-7\n"), 0644); err != nil {
		t.Fatal(err)
	}
	groups := append([]string{"eve", "eve/services"}, leaves...)
	for _, cg := range groups {
		if err := os.MkdirAll(filepath.Join(root, cg), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, cg, "cpuset.cpus"), []byte("0\n"), 0644); err != nil {
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

// Widening must reach every per-service leaf, not just kube:
// 010-eve-cgroup writes eve_max_vcpus into each leaf individually, so
// freeing the ancestors alone frees nothing and freeing only kube leaves
// pillar — which fetches and verifies first-boot images — pinned.
func TestWidenEVECPUsCoversEveryLeafAndRestores(t *testing.T) {
	root := fakeCPUSetTree(t,
		"eve/services/kube", "eve/services/pillar", "eve/services/vtpm")

	loan := WidenEVECPUs()
	if loan == nil {
		t.Fatal("WidenEVECPUs returned nil on a confined tree")
	}
	for _, cg := range []string{
		"eve", "eve/services",
		"eve/services/kube", "eve/services/pillar", "eve/services/vtpm",
	} {
		if got := readMask(t, root, cg); got != "0-7" {
			t.Errorf("%s = %q after widen, want \"0-7\"", cg, got)
		}
	}
	if got := KubeCPUCount(); got != 8 {
		t.Errorf("KubeCPUCount while borrowed = %d, want 8", got)
	}

	loan.Restore()
	for _, cg := range []string{
		"eve", "eve/services",
		"eve/services/kube", "eve/services/pillar", "eve/services/vtpm",
	} {
		if got := readMask(t, root, cg); got != "0" {
			t.Errorf("%s = %q after restore, want \"0\"", cg, got)
		}
	}
	if got := KubeCPUCount(); got != 1 {
		t.Errorf("KubeCPUCount after restore = %d, want 1", got)
	}
}

// One unreadable leaf must not abandon its siblings — each is independent
// once the ancestors are open.
func TestWidenEVECPUsSkipsBadLeafButKeepsSiblings(t *testing.T) {
	root := fakeCPUSetTree(t, "eve/services/kube", "eve/services/broken")
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

// An unwidenable ancestor aborts: cgroup v1 will not let a leaf exceed
// its parent, so widening leaves underneath cannot work.
func TestWidenEVECPUsAbortsOnBadAncestor(t *testing.T) {
	root := fakeCPUSetTree(t, "eve/services/kube")
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
