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
