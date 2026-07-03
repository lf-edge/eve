// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
)

// TestRunWatchdogNoDevice: with no watchdog device present, run-watchdog must
// return 0 immediately (so the caller's long operation proceeds unprotected
// rather than failing). This is the host-side / plain-qemu case.
func TestRunWatchdogNoDevice(t *testing.T) {
	saved := watchdogDevice
	defer func() { watchdogDevice = saved }()
	watchdogDevice = filepath.Join(t.TempDir(), "absent-watchdog")

	if rc := cmdRunWatchdog(nil); rc != 0 {
		t.Fatalf("cmdRunWatchdog with no device = %d, want 0", rc)
	}
}

// TestEscalatedTimeout: the no-pet stress timeout is spread LINEARLY from ~5s to
// ~300s in ~30s steps (jittered), so fires sweep the shrink then the grow before
// later attempts converge; it caps at 300s for attempts past the table.
func TestEscalatedTimeout(t *testing.T) {
	cases := []struct{ attempt, lo, hi int }{
		{0, 5, 14},
		{1, 35, 44},
		{2, 65, 74},
		{3, 95, 104},
		{4, 125, 134},
		{5, 155, 164},
		{6, 185, 194},
		{7, 215, 224},
		{8, 245, 254},
		{9, 300, 309},
		{10, 300, 300},
		{15, 300, 300},
	}
	for _, c := range cases {
		for i := 0; i < 500; i++ {
			got := escalatedTimeout(c.attempt)
			if got < c.lo || got > c.hi {
				t.Fatalf("escalatedTimeout(%d) = %d, want [%d,%d]", c.attempt, got, c.lo, c.hi)
			}
		}
	}
}
