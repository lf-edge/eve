// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Tiny dispatch wrappers — all logs-only no-ops.

func TestHandleNodeAgentStatusDelete(t *testing.T) {
	tc := newTestCtx(t)
	handleNodeAgentStatusDelete(tc.ctx, "any", nil)
}

func TestHandleZbootConfigDelete_UnknownKey(t *testing.T) {
	tc := newTestCtx(t)
	// No matching ZbootStatus published → falls through the unknown
	// branch.
	handleZbootConfigDelete(tc.ctx, "IMGZ", types.ZbootConfig{PartitionLabel: "IMGZ"})
}

func TestHandleZedAgentStatusDelete(t *testing.T) {
	tc := newTestCtx(t)
	handleZedAgentStatusDelete(tc.ctx, "any", nil)
}

func TestHandleNodeDrainStatusDelete(t *testing.T) {
	tc := newTestCtx(t)
	handleNodeDrainStatusDelete(tc.ctx, "any", nil)
}

func TestHandleBaseOsConfigDelete_UnknownKey(t *testing.T) {
	tc := newTestCtx(t)
	// No BaseOsStatus published yet — early return.
	handleBaseOsConfigDelete(tc.ctx, "absent", nil)
}

// maybeRetryInstall has three branches; two are testable without zboot.

func TestMaybeRetryInstall_AllNotTooEarly(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubBaseOsStatus.items["a"] = types.BaseOsStatus{
		ContentTreeUUID: "a",
		TooEarly:        false,
	}
	tc.pubBaseOsStatus.items["b"] = types.BaseOsStatus{
		ContentTreeUUID: "b",
		TooEarly:        false,
	}
	maybeRetryInstall(tc.ctx)
	// All entries should still be present; nothing was retried.
	if got := len(tc.pubBaseOsStatus.items); got != 2 {
		t.Fatalf("expected 2 entries, got %d", got)
	}
}

func TestMaybeRetryInstall_TooEarlyButNoConfig(t *testing.T) {
	tc := newTestCtx(t)
	// TooEarly=true but no matching BaseOsConfig → skipped without
	// invoking baseOsHandleStatusUpdate.
	tc.pubBaseOsStatus.items["a"] = types.BaseOsStatus{
		ContentTreeUUID: "a",
		TooEarly:        true,
	}
	maybeRetryInstall(tc.ctx)
	got, err := tc.pubBaseOsStatus.Get("a")
	if err != nil {
		t.Fatalf("entry vanished: %v", err)
	}
	st := got.(types.BaseOsStatus)
	// TooEarly is unchanged because the retry never fired.
	if !st.TooEarly {
		t.Fatal("TooEarly should remain true when no config matches")
	}
}

// shouldDeferForNodeDrain — only the NOTSUPPORTED short-circuit is
// reachable without a real kubeapi setup. UNKNOWN/NOTREQUESTED/REQUESTED
// branches need a kubeapi seam (Phase 2). NOTSUPPORTED is what every
// non-kubevirt build hits.

func TestShouldDeferForNodeDrain_NotKubeReturnsFalse(t *testing.T) {
	tc := newTestCtx(t)
	// kubeapi.GetNodeDrainStatus on a non-kube subscription returns
	// {Status: NOTSUPPORTED}.
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("non-kube build should never defer")
	}
}

// handleNodeDrainStatusImpl ignores any RequestedBy other than UPDATE;
// that branch is testable without further seams.

func TestHandleNodeDrainStatusImpl_NonUpdateIgnored(t *testing.T) {
	tc := newTestCtx(t)
	tc.ctx.deferredBaseOsID = "uuid-x"
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.NONE,
		Status:      kubeapi.COMPLETE,
	}
	handleNodeDrainStatusImpl(tc.ctx, "global", st, nil)
	// deferredBaseOsID untouched (the COMPLETE branch only fires for
	// RequestedBy==UPDATE).
	if tc.ctx.deferredBaseOsID != "uuid-x" {
		t.Fatalf("deferredBaseOsID changed to %q", tc.ctx.deferredBaseOsID)
	}
}

// Trivial Create / Modify dispatch wrappers — each just forwards to its
// Impl. The fact that they don't panic + the side-effect makes it
// through is the signal.

func TestHandleNodeAgentStatusCreateAndModify(t *testing.T) {
	tc := newTestCtx(t)
	st := types.NodeAgentStatus{RebootReason: "watchdog", RebootImage: "IMGB"}
	handleNodeAgentStatusCreate(tc.ctx, "global", st)
	if tc.ctx.rebootReason != "watchdog" {
		t.Fatalf("Create didn't dispatch")
	}
	tc.ctx.rebootReason = ""
	handleNodeAgentStatusModify(tc.ctx, "global", st, nil)
	if tc.ctx.rebootReason != "watchdog" {
		t.Fatal("Modify didn't dispatch")
	}
}

func TestHandleZbootConfigCreateAndModify(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "inprogress",
		TestComplete:   false,
	}
	tc.zb.parts["IMGA"].state = "inprogress"
	cfg := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: true}
	handleZbootConfigCreate(tc.ctx, "IMGA", cfg)
	if tc.zb.markActiveCalls != 1 {
		t.Fatal("Create didn't dispatch into TestComplete")
	}
	// Modify also flips when the published status' TestComplete diverges
	// from config; reset and try the false-flip path.
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
		TestComplete:   true,
	}
	cfg2 := types.ZbootConfig{PartitionLabel: "IMGA", TestComplete: false}
	handleZbootConfigModify(tc.ctx, "IMGA", cfg2, nil)
	got, _ := tc.pubZbootStatus.Get("IMGA")
	if got.(types.ZbootStatus).TestComplete {
		t.Fatal("Modify didn't dispatch the false-flip")
	}
}

func TestHandleZedAgentStatusCreateAndModify(t *testing.T) {
	// Create on a fresh ctx: the no-file branch in handleForceFallback
	// just saves the initial counter, which is enough to confirm
	// dispatch.
	tcA := newTestCtx(t)
	stA := types.ZedAgentStatus{ForceFallbackCounter: 11}
	handleZedAgentStatusCreate(tcA.ctx, "global", stA)
	if got, _ := readForceFallbackCounter(tcA.ctx); got != 11 {
		t.Fatal("Create didn't dispatch")
	}

	// Modify on a separate fresh ctx: same no-file branch.
	tcB := newTestCtx(t)
	stB := types.ZedAgentStatus{ForceFallbackCounter: 22}
	handleZedAgentStatusModify(tcB.ctx, "global", stB, nil)
	if got, _ := readForceFallbackCounter(tcB.ctx); got != 22 {
		t.Fatal("Modify didn't dispatch")
	}
}

func TestHandleNodeDrainStatusCreateAndModify(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubNodeDrainRequest.items["global"] = kubeapi.NodeDrainRequest{}
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.UPDATE,
		Status:      kubeapi.FAILEDDRAIN,
	}
	handleNodeDrainStatusCreate(tc.ctx, "global", st)
	if _, err := tc.pubNodeDrainRequest.Get("global"); err == nil {
		t.Fatal("Create didn't dispatch unpublish")
	}
	// Re-seed and try Modify.
	tc.pubNodeDrainRequest.items["global"] = kubeapi.NodeDrainRequest{}
	handleNodeDrainStatusModify(tc.ctx, "global", st, nil)
	if _, err := tc.pubNodeDrainRequest.Get("global"); err == nil {
		t.Fatal("Modify didn't dispatch")
	}
}

// handleGlobalConfigCreate/Modify just forward to Impl.

func TestHandleGlobalConfigCreateAndModify_NonGlobalKey(t *testing.T) {
	tc := newTestCtx(t)
	handleGlobalConfigCreate(tc.ctx, "not-global", nil)
	handleGlobalConfigModify(tc.ctx, "not-global", nil, nil)
	if tc.ctx.GCInitialized {
		t.Fatal("non-global key must not flip GCInitialized")
	}
}

// handleBaseOsConfigDeleteByStatus / removeBaseOsConfig

func TestHandleBaseOsConfigDeleteByStatus_RemovesPublication(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	tc.pubBaseOsStatus.items["uuid-x"] = st
	handleBaseOsConfigDeleteByStatus(tc.ctx, "uuid-x", &st)
	if _, err := tc.pubBaseOsStatus.Get("uuid-x"); err == nil {
		t.Fatal("expected entry removed")
	}
}

func TestHandleBaseOsConfigDelete_KnownKeyRemoves(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubBaseOsStatus.items["uuid-x"] = types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	handleBaseOsConfigDelete(tc.ctx, "uuid-x", nil)
	if _, err := tc.pubBaseOsStatus.Get("uuid-x"); err == nil {
		t.Fatal("expected entry removed")
	}
}

// handleContentTreeStatusCreate / Modify / Delete all forward to Impl.

func TestHandleContentTreeStatusWrappers_DispatchSafely(t *testing.T) {
	tc := newTestCtx(t)
	cts := types.ContentTreeStatus{State: types.LOADED}
	handleContentTreeStatusCreate(tc.ctx, "ct-1", cts)
	handleContentTreeStatusModify(tc.ctx, "ct-1", cts, nil)
	handleContentTreeStatusDelete(tc.ctx, "ct-1", cts)
}
