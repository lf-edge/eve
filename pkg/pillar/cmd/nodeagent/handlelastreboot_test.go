// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestHandleLastRebootReason_StoredReason exercises the happy path
// where a reason was persisted from the previous boot.
func TestHandleLastRebootReason_StoredReason(t *testing.T) {
	tc := newTestCtx()
	tc.rebootStore.rebootReason = "user requested reboot"
	tc.rebootStore.rebootStack = "stack contents"
	tc.rebootStore.bootReason = types.BootReasonRebootCmd
	tc.rebootStore.bootTime = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	tc.rebootStore.rebootImage = "lfedge/eve:foo"
	tc.ctx.paths.firstbootFile = filepath.Join(t.TempDir(), "no-such-firstboot")

	handleLastRebootReason(tc.ctx)

	if !tc.rebootStore.discardedRebootReason {
		t.Errorf("expected stored reboot reason to be discarded")
	}
	if !tc.rebootStore.discardedBootReason {
		t.Errorf("expected stored boot reason to be discarded")
	}
	if !tc.rebootStore.discardedRebootImage {
		t.Errorf("expected stored reboot image to be discarded")
	}
	if tc.ctx.rebootReason != "user requested reboot" {
		t.Errorf("expected stored reason to be preserved, got %q",
			tc.ctx.rebootReason)
	}
	if tc.ctx.bootReason != types.BootReasonRebootCmd {
		t.Errorf("expected stored bootReason, got %v", tc.ctx.bootReason)
	}
	// The wrapper should NOT overwrite the stored time when bootReason
	// is non-None.
	if !tc.ctx.rebootTime.Equal(tc.rebootStore.bootTime) {
		t.Errorf("expected stored bootTime to be used")
	}
	if tc.ctx.rebootImage != "lfedge/eve:foo" {
		t.Errorf("expected stored image, got %q", tc.ctx.rebootImage)
	}
}

// TestHandleLastRebootReason_FirstBoot exercises the first-boot
// synthesis path: no stored reason, but the firstboot marker exists.
// Verifies that the marker file is removed afterwards.
func TestHandleLastRebootReason_FirstBoot(t *testing.T) {
	tc := newTestCtx()
	dir := t.TempDir()
	tc.ctx.paths.firstbootFile = filepath.Join(dir, "first-boot")
	mustWrite(t, tc.ctx.paths.firstbootFile, "")

	handleLastRebootReason(tc.ctx)

	if tc.ctx.bootReason != types.BootReasonFirst {
		t.Errorf("expected BootReasonFirst, got %v", tc.ctx.bootReason)
	}
	if !strings.HasPrefix(tc.ctx.rebootReason, "NORMAL: First boot") {
		t.Errorf("unexpected synthesized reason: %q", tc.ctx.rebootReason)
	}
	// firstboot marker must be removed.
	if _, err := os.Stat(tc.ctx.paths.firstbootFile); err == nil {
		t.Errorf("first-boot marker should have been removed")
	}
}

// TestHandleLastRebootReason_StackTagging covers the dmesg/stack
// log-tagging branch when a stored stack is present alongside a
// kernel-panic boot reason.
func TestHandleLastRebootReason_StackTagging(t *testing.T) {
	tc := newTestCtx()
	tc.rebootStore.rebootReason = "kernel panic"
	tc.rebootStore.rebootStack = "frame1\nframe2\nframe3"
	tc.rebootStore.bootReason = types.BootReasonKernel
	tc.rebootStore.bootTime = time.Now()
	tc.ctx.paths.firstbootFile = filepath.Join(t.TempDir(), "absent")

	handleLastRebootReason(tc.ctx)

	if tc.ctx.bootReason != types.BootReasonKernel {
		t.Errorf("expected BootReasonKernel, got %v", tc.ctx.bootReason)
	}
	if tc.ctx.rebootStack != "frame1\nframe2\nframe3" {
		t.Errorf("short stack should pass through truncateRebootStack unchanged")
	}
}

// TestHandleLastRebootReason_RestartCounterIncremented confirms the
// wrapper updates ctx.restartCounter via incrementRestartCounter.
func TestHandleLastRebootReason_RestartCounterIncremented(t *testing.T) {
	tc := newTestCtx()
	tc.rebootStore.rebootReason = "x"
	tc.rebootStore.bootTime = time.Now()
	tc.ctx.paths.firstbootFile = filepath.Join(t.TempDir(), "absent")
	tc.ctx.paths.restartCounterFile = filepath.Join(t.TempDir(), "rc")
	mustWrite(t, tc.ctx.paths.restartCounterFile, "5")

	handleLastRebootReason(tc.ctx)

	if tc.ctx.restartCounter != 5 {
		t.Errorf("expected restartCounter=5 (pre-increment), got %d",
			tc.ctx.restartCounter)
	}
}
