// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestSynthesizeRebootReason_FirstBoot(t *testing.T) {
	initTestLog()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := types.NewSmartDataWithDefaults()
	curr := types.NewSmartDataWithDefaults()

	reason, br := synthesizeRebootReason(true,
		types.BootReasonNone, prev, curr, now)
	if br != types.BootReasonFirst {
		t.Errorf("expected BootReasonFirst, got %s", br)
	}
	if !strings.HasPrefix(reason, "NORMAL: First boot") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestSynthesizeRebootReason_PowerFail(t *testing.T) {
	initTestLog()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := &types.DeviceSmartInfo{PowerCycleCount: 5}
	curr := &types.DeviceSmartInfo{PowerCycleCount: 6}

	reason, br := synthesizeRebootReason(false,
		types.BootReasonNone, prev, curr, now)
	if br != types.BootReasonPowerFail {
		t.Errorf("expected BootReasonPowerFail, got %s", br)
	}
	if !strings.Contains(reason, "device powered off") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestSynthesizeRebootReason_KernelPanic(t *testing.T) {
	initTestLog()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Equal counters → no power cycle, presume kernel panic.
	prev := &types.DeviceSmartInfo{PowerCycleCount: 5}
	curr := &types.DeviceSmartInfo{PowerCycleCount: 5}

	reason, br := synthesizeRebootReason(false,
		types.BootReasonNone, prev, curr, now)
	if br != types.BootReasonKernel {
		t.Errorf("expected BootReasonKernel, got %s", br)
	}
	if !strings.Contains(reason, "kernel panic") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestSynthesizeRebootReason_Unknown_NoSmart(t *testing.T) {
	initTestLog()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := types.NewSmartDataWithDefaults() // PowerCycleCount = -1
	curr := types.NewSmartDataWithDefaults() // PowerCycleCount = -1

	reason, br := synthesizeRebootReason(false,
		types.BootReasonNone, prev, curr, now)
	if br != types.BootReasonUnknown {
		t.Errorf("expected BootReasonUnknown, got %s", br)
	}
	if !strings.Contains(reason, "Unknown reboot reason") {
		t.Errorf("unexpected reason: %q", reason)
	}
}

func TestSynthesizeRebootReason_StoredBootReasonWins(t *testing.T) {
	initTestLog()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := &types.DeviceSmartInfo{PowerCycleCount: 5}
	curr := &types.DeviceSmartInfo{PowerCycleCount: 6}

	// A non-None stored boot reason must NOT be overwritten by the
	// power-cycle heuristic.
	_, br := synthesizeRebootReason(false,
		types.BootReasonFatal, prev, curr, now)
	if br != types.BootReasonFatal {
		t.Errorf("stored bootReason should win, got %s", br)
	}
}

func TestTruncateRebootStack_ShortUnchanged(t *testing.T) {
	in := strings.Repeat("a", 100)
	if got := truncateRebootStack(in); got != in {
		t.Errorf("short stack should not be truncated")
	}
}

func TestTruncateRebootStack_LongTailKept(t *testing.T) {
	// Build a stack much longer than maxJSONAttributeSize.
	in := strings.Repeat("X", maxJSONAttributeSize) +
		"BOTTOMOFSTACK"
	got := truncateRebootStack(in)
	if !strings.HasPrefix(got, "...\n") {
		t.Errorf("truncated stack should start with marker, got %q",
			got[:10])
	}
	if !strings.HasSuffix(got, "BOTTOMOFSTACK") {
		t.Errorf("truncated stack should preserve tail, got tail %q",
			got[len(got)-15:])
	}
	// Truncated payload (excluding the leading "...\n") must not exceed
	// maxRebootStackSize runes.
	body := strings.TrimPrefix(got, "...\n")
	if len([]rune(body)) > maxRebootStackSize {
		t.Errorf("truncated body exceeds maxRebootStackSize: %d",
			len([]rune(body)))
	}
}
