// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// getPartitionState

func TestGetPartitionState_PreferPublishedMirror(t *testing.T) {
	tc := newTestCtx(t)
	// Mirror reports "inprogress" for IMGB even though mockZboot says
	// "unused" — the mirror should win.
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
	}
	if got := getPartitionState(tc.ctx, "IMGB"); got != "inprogress" {
		t.Fatalf("got %q want inprogress (from mirror)", got)
	}
}

func TestGetPartitionState_FallbackToZbootWhenNoMirror(t *testing.T) {
	tc := newTestCtx(t)
	// No ZbootStatus published; falls back to ctx.zboot.GetPartitionState.
	if got := getPartitionState(tc.ctx, "IMGB"); got != "unused" {
		t.Fatalf("got %q want unused (from zboot fallback)", got)
	}
}

// createZbootStatus

func TestCreateZbootStatus_FromZboot(t *testing.T) {
	tc := newTestCtx(t)
	tc.zb.parts["IMGA"].short = "13.4.0"
	tc.zb.parts["IMGA"].long = "13.4.0-kvm-amd64"
	got := createZbootStatus(tc.ctx, "IMGA")
	if got == nil {
		t.Fatal("expected status, got nil")
	}
	if got.PartitionLabel != "IMGA" || got.PartitionState != "active" ||
		got.ShortVersion != "13.4.0" || got.LongVersion != "13.4.0-kvm-amd64" ||
		!got.CurrentPartition || got.TestComplete {
		t.Fatalf("unexpected status: %+v", got)
	}
}

func TestCreateZbootStatus_TrimsSpaces(t *testing.T) {
	tc := newTestCtx(t)
	if got := createZbootStatus(tc.ctx, "  IMGA  "); got == nil ||
		got.PartitionLabel != "IMGA" {
		t.Fatalf("expected trim to IMGA, got %+v", got)
	}
}

func TestCreateZbootStatus_InvalidLabelReturnsNil(t *testing.T) {
	tc := newTestCtx(t)
	if got := createZbootStatus(tc.ctx, "IMGZ"); got != nil {
		t.Fatalf("expected nil for invalid label, got %+v", got)
	}
}

func TestCreateZbootStatus_ShortVersionErrorIsLogged(t *testing.T) {
	tc := newTestCtx(t)
	tc.zb.parts["IMGA"].shortErr = errBoom
	// The function only logs the error and continues; the rest of the
	// status should still be populated.
	got := createZbootStatus(tc.ctx, "IMGA")
	if got == nil || got.PartitionState != "active" {
		t.Fatalf("expected populated status, got %+v", got)
	}
}

// getZbootStatus

func TestGetZbootStatus_TrimsAndValidates(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{PartitionLabel: "IMGA"}

	if got := getZbootStatus(tc.ctx, "  IMGA  "); got == nil ||
		got.PartitionLabel != "IMGA" {
		t.Fatalf("expected hit after trim, got %+v", got)
	}
	if got := getZbootStatus(tc.ctx, "IMGZ"); got != nil {
		t.Fatalf("expected nil for invalid label, got %+v", got)
	}
	if got := getZbootStatus(tc.ctx, "IMGB"); got != nil {
		t.Fatalf("expected nil for absent IMGB, got %+v", got)
	}
}

// updateAndPublishZbootStatus

func TestUpdateAndPublishZbootStatus_RefreshesStateAndCurrent(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel:   "IMGB",
		PartitionState:   "unused",
		CurrentPartition: false,
	}
	// Drive a state change via the mock
	tc.zb.parts["IMGB"].state = "updating"
	updateAndPublishZbootStatus(tc.ctx, "IMGB", false)

	got, err := tc.pubZbootStatus.Get("IMGB")
	if err != nil {
		t.Fatalf("not published: %v", err)
	}
	st := got.(types.ZbootStatus)
	if st.PartitionState != "updating" {
		t.Fatalf("PartitionState=%q want updating", st.PartitionState)
	}
}

func TestUpdateAndPublishZbootStatus_RefreshesVersionsWhenAsked(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		ShortVersion:   "old",
	}
	tc.zb.parts["IMGA"].short = "new"
	tc.zb.parts["IMGA"].long = "long-new"
	updateAndPublishZbootStatus(tc.ctx, "IMGA", true)

	got, _ := tc.pubZbootStatus.Get("IMGA")
	st := got.(types.ZbootStatus)
	if st.ShortVersion != "new" || st.LongVersion != "long-new" {
		t.Fatalf("versions not refreshed: %+v", st)
	}
}

func TestUpdateAndPublishZbootStatus_InvalidLabelIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	updateAndPublishZbootStatus(tc.ctx, "IMGZ", true)
	if got := len(tc.pubZbootStatus.items); got != 0 {
		t.Fatalf("nothing should be published; got %d entries", got)
	}
}

func TestUpdateAndPublishZbootStatus_NoExistingStatusIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	updateAndPublishZbootStatus(tc.ctx, "IMGA", false)
	if _, err := tc.pubZbootStatus.Get("IMGA"); err == nil {
		t.Fatal("nothing should have been published")
	}
}

// updateAndPublishZbootStatusAll

func TestUpdateAndPublishZbootStatusAll_SeedsBothPartitions(t *testing.T) {
	tc := newTestCtx(t)
	tc.zb.parts["IMGA"].short = "13.4"
	tc.zb.parts["IMGB"].short = ""
	updateAndPublishZbootStatusAll(tc.ctx)

	a, errA := tc.pubZbootStatus.Get("IMGA")
	b, errB := tc.pubZbootStatus.Get("IMGB")
	if errA != nil || errB != nil {
		t.Fatalf("missing publishes: %v / %v", errA, errB)
	}
	stA := a.(types.ZbootStatus)
	stB := b.(types.ZbootStatus)
	if stA.PartitionState != "active" || !stA.CurrentPartition ||
		stA.ShortVersion != "13.4" {
		t.Fatalf("IMGA wrong: %+v", stA)
	}
	if stB.PartitionState != "unused" || stB.CurrentPartition {
		t.Fatalf("IMGB wrong: %+v", stB)
	}
}

func TestUpdateAndPublishZbootStatusAll_RefreshesExisting(t *testing.T) {
	tc := newTestCtx(t)
	// Pre-populate stale status for IMGB.
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	tc.zb.parts["IMGB"].state = "updating"
	updateAndPublishZbootStatusAll(tc.ctx)

	got, _ := tc.pubZbootStatus.Get("IMGB")
	st := got.(types.ZbootStatus)
	if st.PartitionState != "updating" {
		t.Fatalf("expected refresh to updating, got %q", st.PartitionState)
	}
}

// baseOsSetPartitionInfoInStatus

func TestBaseOsSetPartitionInfoInStatus_MissingZbootStatusIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{
		PartitionLabel: "old",
		PartitionState: "old-state",
	}
	baseOsSetPartitionInfoInStatus(tc.ctx, &st, "IMGA")
	// No published ZbootStatus for IMGA; no fields should change.
	if st.PartitionLabel != "old" || st.PartitionState != "old-state" {
		t.Fatalf("unexpected mutation: %+v", st)
	}
}

func TestBaseOsSetPartitionInfoInStatus_CopiesFromMirror(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel:   "IMGA",
		PartitionState:   "active",
		PartitionDevname: "/dev/sda3",
	}
	st := types.BaseOsStatus{}
	baseOsSetPartitionInfoInStatus(tc.ctx, &st, "IMGA")
	if st.PartitionLabel != "IMGA" || st.PartitionState != "active" ||
		st.PartitionDevice != "/dev/sda3" {
		t.Fatalf("unexpected: %+v", st)
	}
}

// baseOsGetActivationStatus

func TestBaseOsGetActivationStatus_EmptyLabelClearsActivated(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{Activated: true} // no PartitionLabel
	if !baseOsGetActivationStatus(tc.ctx, &st) {
		t.Fatal("expected change")
	}
	if st.Activated {
		t.Fatal("Activated should have been cleared")
	}
}

func TestBaseOsGetActivationStatus_NoPartStatusClearsActivated(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{Activated: true, PartitionLabel: "IMGB"}
	// No published ZbootStatus for IMGB.
	if !baseOsGetActivationStatus(tc.ctx, &st) {
		t.Fatal("expected change")
	}
	if st.Activated {
		t.Fatal("Activated should have been cleared")
	}
}

func TestBaseOsGetActivationStatus_OtherPartitionAlwaysFalse(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel:   "IMGB",
		PartitionState:   "updating",
		CurrentPartition: false,
	}
	st := types.BaseOsStatus{Activated: true, PartitionLabel: "IMGB"}
	if !baseOsGetActivationStatus(tc.ctx, &st) {
		t.Fatal("expected change")
	}
	if st.Activated {
		t.Fatal("Activated must be false on the non-current partition")
	}
}

func TestBaseOsGetActivationStatus_CurrentActivePartitionIsActivated(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel:   "IMGA",
		PartitionState:   "active",
		CurrentPartition: true,
	}
	st := types.BaseOsStatus{PartitionLabel: "IMGA"}
	if !baseOsGetActivationStatus(tc.ctx, &st) {
		t.Fatal("expected change")
	}
	if !st.Activated {
		t.Fatal("Activated should be true on current=active")
	}
}

func TestBaseOsGetActivationStatus_CurrentInprogressNotActivated(t *testing.T) {
	tc := newTestCtx(t)
	// Current partition "IMGA" but it's still inprogress (post-upgrade
	// test window); not yet activated from baseosmgr's perspective.
	tc.zb.parts["IMGA"].state = "inprogress"
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel:   "IMGA",
		PartitionState:   "inprogress",
		CurrentPartition: true,
	}
	st := types.BaseOsStatus{PartitionLabel: "IMGA", Activated: true}
	if !baseOsGetActivationStatus(tc.ctx, &st) {
		t.Fatal("expected change (Activated should clear)")
	}
	if st.Activated {
		t.Fatal("Activated should clear when partition not active")
	}
}
