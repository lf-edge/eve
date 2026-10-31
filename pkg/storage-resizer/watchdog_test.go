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

// TestEscalatedTimeout: the no-pet stress timeout packs its first eight rungs below
// 65s (jittered), so their ~2x resets land inside the ~130s shrink -- the step that
// relocates data -- before the last two rungs let the resize converge; it caps at
// 300s for attempts past the table.
func TestEscalatedTimeout(t *testing.T) {
	cases := []struct{ attempt, lo, hi int }{
		{0, 5, 14},
		{1, 13, 22},
		{2, 21, 30},
		{3, 29, 38},
		{4, 37, 46},
		{5, 45, 54},
		{6, 53, 62},
		{7, 61, 70},
		{8, 155, 164},
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
