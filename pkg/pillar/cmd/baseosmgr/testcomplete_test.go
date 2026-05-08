// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// handleZbootTestComplete is the inbound side of nodeagent's
// "post-upgrade test passed" signal. The success path flips
// MarkCurrentPartitionStateActive on zboot, mirrors TestComplete=true
// into ZbootStatus, and republishes BaseOsStatus.

func TestHandleZbootTestComplete_NoChangeIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	st := types.ZbootStatus{PartitionLabel: "IMGA", TestComplete: true}
	handleZbootTestComplete(tc.ctx, cfg, st)
	if tc.zb.markActiveCalls != 0 {
		t.Fatalf("must not call MarkCurrentPartitionStateActive: %d", tc.zb.markActiveCalls)
	}
}

func TestHandleZbootTestComplete_NotCurrentPartitionIgnored(t *testing.T) {
	tc := newTestCtx(t)
	// Asked to commit IMGB but current partition is IMGA → ignore.
	cfg := types.ZbootConfig{PartitionLabel: "IMGB", TestComplete: true}
	st := types.ZbootStatus{PartitionLabel: "IMGB"}
	handleZbootTestComplete(tc.ctx, cfg, st)
	if tc.zb.markActiveCalls != 0 {
		t.Fatalf("must not commit IMGB while current=IMGA")
	}
}

func TestHandleZbootTestComplete_CurrentNotInprogressIgnored(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active", // not inprogress
	}
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	st := types.ZbootStatus{PartitionLabel: "IMGA"}
	handleZbootTestComplete(tc.ctx, cfg, st)
	if tc.zb.markActiveCalls != 0 {
		t.Fatalf("must not commit when curr is not inprogress")
	}
}

func TestHandleZbootTestComplete_HappyPath(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "inprogress", // commit-eligible
		ShortVersion:   "14.0",
	}
	tc.zb.parts["IMGA"].state = "inprogress"
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	st := types.ZbootStatus{PartitionLabel: "IMGA"}
	handleZbootTestComplete(tc.ctx, cfg, st)

	if tc.zb.markActiveCalls != 1 {
		t.Fatalf("MarkCurrentPartitionStateActive call count = %d, want 1",
			tc.zb.markActiveCalls)
	}
	got, _ := tc.pubZbootStatus.Get("IMGA")
	zst := got.(types.ZbootStatus)
	if !zst.TestComplete {
		t.Fatal("ZbootStatus.TestComplete should have been mirrored to true")
	}
}

func TestHandleZbootTestComplete_MarkActiveErrorRecorded(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "inprogress",
		ShortVersion:   "14.0",
	}
	tc.zb.parts["IMGA"].state = "inprogress"
	tc.zb.markActiveErr = errBoom
	// Need a BaseOsStatus keyed by partLabel for the error to be recorded.
	tc.pubBaseOsStatus.items["IMGA"] = types.BaseOsStatus{
		ContentTreeUUID: "IMGA",
		BaseOsVersion:   "14.0",
		PartitionLabel:  "IMGA",
	}
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	st := types.ZbootStatus{PartitionLabel: "IMGA"}
	handleZbootTestComplete(tc.ctx, cfg, st)

	got, _ := tc.pubBaseOsStatus.Get("IMGA")
	bst := got.(types.BaseOsStatus)
	if !bst.HasError() {
		t.Fatalf("expected error on BaseOsStatus, got %+v", bst)
	}
	// TestComplete must NOT have been mirrored to true on failure.
	zst, _ := tc.pubZbootStatus.Get("IMGA")
	if zst.(types.ZbootStatus).TestComplete {
		t.Fatal("TestComplete should remain false on Mark failure")
	}
}

func TestHandleZbootTestComplete_FalseFlipMirrorsAndRepublishes(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
		TestComplete:   true,
	}
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: false}
	st := types.ZbootStatus{PartitionLabel: "IMGA", TestComplete: true}
	handleZbootTestComplete(tc.ctx, cfg, st)

	got, _ := tc.pubZbootStatus.Get("IMGA")
	if got.(types.ZbootStatus).TestComplete {
		t.Fatal("TestComplete should have been flipped to false")
	}
	if tc.zb.markActiveCalls != 0 {
		t.Fatal("false-flip path must not call Mark")
	}
}

// handleZbootConfigImpl: only fires through to handleZbootTestComplete
// when the config and status disagree on TestComplete.

func TestHandleZbootConfigImpl_NoStatusIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	// No ZbootStatus published.
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	handleZbootConfigImpl(tc.ctx, "IMGA", cfg)
}

func TestHandleZbootConfigImpl_FlipTriggersTestComplete(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "inprogress",
		TestComplete:   false,
	}
	tc.zb.parts["IMGA"].state = "inprogress"
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	handleZbootConfigImpl(tc.ctx, "IMGA", cfg)
	if tc.zb.markActiveCalls != 1 {
		t.Fatalf("expected Mark to fire, got %d", tc.zb.markActiveCalls)
	}
}

func TestHandleZbootConfigImpl_NoFlipDoesNotTrigger(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
		TestComplete:   true,
	}
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	handleZbootConfigImpl(tc.ctx, "IMGA", cfg)
	if tc.zb.markActiveCalls != 0 {
		t.Fatal("no flip → no Mark")
	}
}
