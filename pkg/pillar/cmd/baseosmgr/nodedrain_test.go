// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// shouldDeferForNodeDrain: branch coverage. The seam returns whatever
// drainStatus tc.drainStatus is set to; the default is NOTSUPPORTED so
// non-kube tests get the production short-circuit for free.

func TestShouldDeferForNodeDrain_UnknownIsNotDeferred(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.UNKNOWN}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("UNKNOWN must not defer (early-boot fast path)")
	}
}

func TestShouldDeferForNodeDrain_NotRequestedRequestsAndDefers(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.NOTREQUESTED}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if !shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("NOTREQUESTED must defer")
	}
	if got := len(tc.drainRequestCalls); got != 1 ||
		tc.drainRequestCalls[0] != kubeapi.UPDATE {
		t.Fatalf("expected one UPDATE drain request, got %v",
			tc.drainRequestCalls)
	}
	if tc.ctx.deferredBaseOsID != "uuid-x" {
		t.Fatalf("deferredBaseOsID = %q want uuid-x",
			tc.ctx.deferredBaseOsID)
	}
}

func TestShouldDeferForNodeDrain_FailedDrainRetriedAndDefers(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.FAILEDDRAIN}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if !shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("FAILEDDRAIN must defer + re-request")
	}
	if len(tc.drainRequestCalls) != 1 {
		t.Fatalf("expected re-request, got %d", len(tc.drainRequestCalls))
	}
}

func TestShouldDeferForNodeDrain_FailedCordonRetriedAndDefers(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.FAILEDCORDON}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if !shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("FAILEDCORDON must defer")
	}
}

func TestShouldDeferForNodeDrain_RequestedJustDefers(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.REQUESTED}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if !shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("REQUESTED must defer")
	}
	if len(tc.drainRequestCalls) != 0 {
		t.Fatal("REQUESTED state must NOT re-request")
	}
}

func TestShouldDeferForNodeDrain_StartingJustDefers(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.STARTING}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if !shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("STARTING must defer")
	}
}

func TestShouldDeferForNodeDrain_CompleteAllowsContinue(t *testing.T) {
	tc := newTestCtx(t)
	tc.drainStatus = &kubeapi.NodeDrainStatus{Status: kubeapi.COMPLETE}
	cfg := &types.BaseOsConfig{ContentTreeUUID: "uuid-x"}
	st := &types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	if shouldDeferForNodeDrain(tc.ctx, "uuid-x", cfg, st) {
		t.Fatal("COMPLETE must allow continue")
	}
	// deferredBaseOsID still gets stamped (production code does this for
	// any non-NOTSUPPORTED/UNKNOWN branch, including COMPLETE).
	if tc.ctx.deferredBaseOsID != "uuid-x" {
		t.Fatalf("expected deferredBaseOsID stamped, got %q",
			tc.ctx.deferredBaseOsID)
	}
}

// handleNodeDrainStatusImpl

func TestHandleNodeDrainStatusImpl_FailedCordonUnpublishesRequest(t *testing.T) {
	tc := newTestCtx(t)
	// Pre-publish a NodeDrainRequest so we can confirm it's removed.
	tc.pubNodeDrainRequest.items["global"] = kubeapi.NodeDrainRequest{}
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.UPDATE,
		Status:      kubeapi.FAILEDCORDON,
	}
	handleNodeDrainStatusImpl(tc.ctx, "global", st, nil)
	if _, err := tc.pubNodeDrainRequest.Get("global"); err == nil {
		t.Fatal("expected NodeDrainRequest to be unpublished")
	}
}

func TestHandleNodeDrainStatusImpl_FailedDrainUnpublishesRequest(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubNodeDrainRequest.items["global"] = kubeapi.NodeDrainRequest{}
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.UPDATE,
		Status:      kubeapi.FAILEDDRAIN,
	}
	handleNodeDrainStatusImpl(tc.ctx, "global", st, nil)
	if _, err := tc.pubNodeDrainRequest.Get("global"); err == nil {
		t.Fatal("expected NodeDrainRequest to be unpublished")
	}
}

func TestHandleNodeDrainStatusImpl_CompleteWithoutDeferredIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.UPDATE,
		Status:      kubeapi.COMPLETE,
	}
	handleNodeDrainStatusImpl(tc.ctx, "global", st, nil)
	// deferredBaseOsID still empty → nothing to do, nothing to publish.
	if got := len(tc.pubBaseOsStatus.items); got != 0 {
		t.Fatalf("expected nothing published, got %d", got)
	}
}

func TestHandleNodeDrainStatusImpl_CompleteWithDeferredDispatches(t *testing.T) {
	tc := newTestCtx(t)
	tc.ctx.deferredBaseOsID = "uuid-x"
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.UPDATE,
		Status:      kubeapi.COMPLETE,
	}
	// No matching BaseOsConfig; baseOsHandleStatusUpdateUUID just
	// logs and returns. The fact that this doesn't panic is the
	// signal that the dispatch happened safely.
	handleNodeDrainStatusImpl(tc.ctx, "global", st, nil)
}

func TestHandleNodeDrainStatusImpl_BadConfigArgIsLogged(t *testing.T) {
	tc := newTestCtx(t)
	// Wrong type in configArg → guarded early-return (logs but no panic).
	handleNodeDrainStatusImpl(tc.ctx, "global", "not-a-NodeDrainStatus", nil)
}

func TestHandleNodeDrainStatusImpl_BadCtxArgIsLogged(t *testing.T) {
	st := kubeapi.NodeDrainStatus{
		RequestedBy: kubeapi.UPDATE,
		Status:      kubeapi.COMPLETE,
	}
	// Wrong type for ctxArg.
	handleNodeDrainStatusImpl("not-a-ctx", "global", st, nil)
}
