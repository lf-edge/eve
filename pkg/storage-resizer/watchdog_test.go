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

// TestEscalatedTimeout: the no-pet stress timeout grows with the attempt and is
// random within each band, reaching the effectively-non-firing 600s by the 4th
// try (attempt index 3).
func TestEscalatedTimeout(t *testing.T) {
	cases := []struct{ attempt, lo, hi int }{
		{0, 10, 20},
		{1, 20, 40},
		{2, 45, 90},
		{3, 600, 600},
		{5, 600, 600},
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
