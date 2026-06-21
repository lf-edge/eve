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
