// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// shadowWaitDir points the breakpoint directory at a temp dir for the
// lifetime of one test.
func shadowWaitDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "k3s")
	orig := state.WaitItemDir
	state.WaitItemDir = dir
	t.Cleanup(func() { state.WaitItemDir = orig })
	return dir
}

// TestBreakSetClearRoundTrip is the operator's whole workflow, and
// pins that set writes the exact path WaitForItem stats.
func TestBreakSetClearRoundTrip(t *testing.T) {
	dir := shadowWaitDir(t)

	if rc := runBreak([]string{"set", "longhorn"}); rc != 0 {
		t.Fatalf("break set: rc=%d", rc)
	}
	want := filepath.Join(dir, "wait_longhorn")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected breakpoint file at %s: %v", want, err)
	}
	if got := state.ItemPath("longhorn"); got != want {
		t.Errorf("CLI and daemon disagree on path: %s vs %s", want, got)
	}

	names, err := stagedBreakpoints()
	if err != nil {
		t.Fatalf("stagedBreakpoints: %v", err)
	}
	if !slices.Equal(names, []string{"longhorn"}) {
		t.Errorf("stagedBreakpoints = %v, want [longhorn]", names)
	}

	if rc := runBreak([]string{"clear", "longhorn"}); rc != 0 {
		t.Fatalf("break clear: rc=%d", rc)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Errorf("breakpoint file survived clear (stat err = %v)", err)
	}
}

// TestBreakSetIsIdempotent — staging twice must not fail; an operator
// re-running the command should not have to care.
func TestBreakSetIsIdempotent(t *testing.T) {
	shadowWaitDir(t)
	for i := range 2 {
		if rc := runBreak([]string{"set", "kubevirt"}); rc != 0 {
			t.Fatalf("break set attempt %d: rc=%d", i+1, rc)
		}
	}
}

// TestBreakClearMissingIsNotAnError — clearing what was never set is a
// no-op, so a cleanup script can run unconditionally.
func TestBreakClearMissingIsNotAnError(t *testing.T) {
	shadowWaitDir(t)
	if rc := runBreak([]string{"clear", "cdi"}); rc != 0 {
		t.Errorf("clearing an unset breakpoint: rc=%d, want 0", rc)
	}
}

func TestBreakClearAll(t *testing.T) {
	shadowWaitDir(t)
	for _, n := range []string{"longhorn", "kubevirt", "wait"} {
		if rc := runBreak([]string{"set", n}); rc != 0 {
			t.Fatalf("set %s: rc=%d", n, rc)
		}
	}
	if rc := runBreak([]string{"clear", "--all"}); rc != 0 {
		t.Fatalf("clear --all: rc=%d", rc)
	}
	names, err := stagedBreakpoints()
	if err != nil {
		t.Fatalf("stagedBreakpoints: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("breakpoints survived clear --all: %v", names)
	}
}

// TestValidBreakNameRejectsTraversal — the name becomes a filename, so
// a path in it would write outside the breakpoint directory.
func TestValidBreakNameRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"", "..", ".", "../../etc/passwd", "a/b", `a\b`} {
		if err := validBreakName(bad); err == nil {
			t.Errorf("validBreakName(%q) = nil, want an error", bad)
		}
	}
	for _, good := range []string{"longhorn", "k3s-install", "wait"} {
		if err := validBreakName(good); err != nil {
			t.Errorf("validBreakName(%q) = %v, want nil", good, err)
		}
	}
}

// TestStagedBreakpointsIgnoresForeignEntries — /persist/k3s holds more
// than breakpoints, so only wait_* files count.
func TestStagedBreakpointsIgnoresForeignEntries(t *testing.T) {
	dir := shadowWaitDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "wait_notafile"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []string{"initial_k3s_version", "wait_longhorn"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	names, err := stagedBreakpoints()
	if err != nil {
		t.Fatalf("stagedBreakpoints: %v", err)
	}
	if !slices.Equal(names, []string{"longhorn"}) {
		t.Errorf("stagedBreakpoints = %v, want [longhorn]", names)
	}
}

// TestBreakRejectsUnknownAction keeps a typo from silently doing
// nothing and reporting success.
func TestBreakRejectsUnknownAction(t *testing.T) {
	shadowWaitDir(t)
	for _, args := range [][]string{{}, {"toggle", "x"}, {"set"}, {"set", "a", "b"}, {"clear"}} {
		if rc := runBreak(args); rc == 0 {
			t.Errorf("runBreak(%v) = 0, want non-zero", args)
		}
	}
}
