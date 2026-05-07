// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// seedZbootPartitions populates the test ctx with two-partition zboot
// state. The current partition is always IMGA; otherState lets the test
// pick the *other* partition's state ("inprogress", "active", "updating").
func seedZbootPartitions(tc *testCtx, currentState, otherState string) {
	tc.subZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel:   "IMGA",
		PartitionState:   currentState,
		ShortVersion:     "v1",
		CurrentPartition: true,
	}
	tc.subZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel:   "IMGB",
		PartitionState:   otherState,
		ShortVersion:     "v2",
		CurrentPartition: false,
	}
	tc.pubZbootConfig.items["IMGA"] = types.ZbootConfig{PartitionLabel: "IMGA"}
	tc.pubZbootConfig.items["IMGB"] = types.ZbootConfig{PartitionLabel: "IMGB"}
}

func TestHandleZbootStatus_OtherUpdatingSchedulesReboot(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.curPart = "IMGA"
	seedZbootPartitions(tc, "inprogress", "updating")

	// IMGB is the one that just became updating; the handler is
	// invoked for IMGB.
	imgb := tc.subZbootStatus.items["IMGB"].(types.ZbootStatus)
	handleZbootStatusImpl(tc.ctx, "IMGB", imgb)

	if len(tc.scheduledOps) != 1 {
		t.Fatalf("expected reboot scheduled, got %d", len(tc.scheduledOps))
	}
	got := tc.scheduledOps[0]
	if got.bootRsn != types.BootReasonUpdate {
		t.Errorf("expected BootReasonUpdate, got %v", got.bootRsn)
	}
	if got.op != types.DeviceOperationReboot {
		t.Errorf("expected reboot op, got %v", got.op)
	}
}

func TestHandleZbootStatus_CurrentBecomesActive(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.curPart = "IMGA"
	tc.ctx.updateInprogress = true
	tc.ctx.testComplete = true
	tc.ctx.updateComplete = true
	seedZbootPartitions(tc, "active", "unused")

	// Mark current state in the in-memory map AS active.
	imga := tc.subZbootStatus.items["IMGA"].(types.ZbootStatus)
	handleZbootStatusImpl(tc.ctx, "IMGA", imga)

	if tc.ctx.updateInprogress {
		t.Errorf("updateInprogress should be cleared once curPart is active")
	}
	if tc.ctx.testComplete {
		t.Errorf("testComplete should be cleared once curPart is active")
	}
	if tc.ctx.updateComplete {
		t.Errorf("updateComplete should be cleared once curPart is active")
	}
}

func TestDoZbootBaseOsTestValidationComplete_Acks(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.curPart = "IMGA"
	tc.ctx.updateInprogress = true
	tc.ctx.updateComplete = false
	tc.pubZbootConfig.items["IMGA"] = types.ZbootConfig{
		PartitionLabel: "IMGA",
		TestComplete:   true, // we previously asked for it
	}

	doZbootBaseOsTestValidationComplete(tc.ctx, "IMGA",
		types.ZbootStatus{
			PartitionLabel: "IMGA",
			TestComplete:   true,
		})

	if !tc.ctx.updateComplete {
		t.Errorf("expected updateComplete=true")
	}
	got := tc.pubZbootConfig.items["IMGA"].(types.ZbootConfig)
	if got.TestComplete {
		t.Errorf("expected TestComplete=false after ack, got true")
	}
}

func TestDoZbootBaseOsTestValidationComplete_NoUpgrade(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.updateInprogress = false

	doZbootBaseOsTestValidationComplete(tc.ctx, "IMGA",
		types.ZbootStatus{PartitionLabel: "IMGA", TestComplete: true})

	if tc.ctx.updateComplete {
		t.Errorf("no-op when no upgrade in progress")
	}
}

func TestInitiateBaseOsControllerTestComplete(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.curPart = "IMGA"
	tc.ctx.updateInprogress = true
	tc.subZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", ShortVersion: "v2",
		CurrentPartition: true, PartitionState: "inprogress",
	}
	tc.pubZbootConfig.items["IMGA"] = types.ZbootConfig{
		PartitionLabel: "IMGA",
	}

	initiateBaseOsControllerTestComplete(tc.ctx)

	if !tc.ctx.testComplete {
		t.Errorf("expected testComplete=true")
	}
	got := tc.pubZbootConfig.items["IMGA"].(types.ZbootConfig)
	if !got.TestComplete {
		t.Errorf("expected ZbootConfig.TestComplete=true after initiate")
	}
}

func TestPublishZbootConfigAll(t *testing.T) {
	tc := newTestCtx()
	publishZbootConfigAll(tc.ctx)

	for _, label := range []string{"IMGA", "IMGB"} {
		got, err := tc.pubZbootConfig.Get(label)
		if err != nil {
			t.Errorf("expected ZbootConfig for %s, got err %v", label, err)
			continue
		}
		cfg := got.(types.ZbootConfig)
		if cfg.PartitionLabel != label {
			t.Errorf("partition label mismatch: got %q want %q",
				cfg.PartitionLabel, label)
		}
	}
}

func TestPublishZbootConfig_InvalidLabelRejected(t *testing.T) {
	tc := newTestCtx()
	tc.zboot.validLabels = map[string]bool{} // nothing is valid

	publishZbootConfig(tc.ctx, types.ZbootConfig{PartitionLabel: "IMGA"})

	if _, err := tc.pubZbootConfig.Get("IMGA"); err == nil {
		t.Errorf("expected publish to be rejected for invalid label")
	}
}

func TestGetZbootConfigAll(t *testing.T) {
	tc := newTestCtx()
	publishZbootConfigAll(tc.ctx)

	cfgs := getZbootConfigAll(tc.ctx)
	if len(cfgs) != 2 {
		t.Errorf("expected 2 configs, got %d", len(cfgs))
	}
}

func TestGetZbootConfigAll_Empty(t *testing.T) {
	tc := newTestCtx()
	cfgs := getZbootConfigAll(tc.ctx)
	if len(cfgs) != 0 {
		t.Errorf("expected empty config list, got %d", len(cfgs))
	}
}

func TestHandleDeviceTimers_NoOpBaseline(t *testing.T) {
	// handleDeviceTimers calls all four health-timer handlers in
	// sequence. With a fresh context, all four should be no-ops.
	tc := newTestCtx()
	handleDeviceTimers(tc.ctx)
	if len(tc.scheduledOps) != 0 {
		t.Errorf("baseline ctx should not schedule any ops, got %d",
			len(tc.scheduledOps))
	}
}

func TestInitiateBaseOsControllerTestComplete_AlreadySet(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.curPart = "IMGA"
	tc.ctx.updateInprogress = true
	tc.subZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", CurrentPartition: true,
	}
	tc.pubZbootConfig.items["IMGA"] = types.ZbootConfig{
		PartitionLabel: "IMGA",
		TestComplete:   true, // already set
	}

	initiateBaseOsControllerTestComplete(tc.ctx)

	// The function logs an error and returns; ctx.testComplete stays
	// false (it was never flipped on this path).
	if tc.ctx.testComplete {
		t.Errorf("testComplete should not be flipped when already set")
	}
}
