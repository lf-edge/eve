// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// checkContentTreeStatus

func TestCheckContentTreeStatus_Missing(t *testing.T) {
	tc := newTestCtx(t)
	got := checkContentTreeStatus(tc.ctx, types.INITIAL, "absent")
	if got.MinState != types.DOWNLOADING {
		t.Fatalf("MinState=%v want DOWNLOADING", got.MinState)
	}
	if !got.Changed {
		t.Fatal("Changed should be true when state moves")
	}
	if got.AllErrors != "" {
		t.Fatalf("AllErrors=%q expected empty", got.AllErrors)
	}
}

func TestCheckContentTreeStatus_Present_LoadedNoChange(t *testing.T) {
	tc := newTestCtx(t)
	tc.subContentTreeStatus.items["ct-1"] = types.ContentTreeStatus{
		State: types.LOADED,
	}
	got := checkContentTreeStatus(tc.ctx, types.LOADED, "ct-1")
	if got.MinState != types.LOADED {
		t.Fatalf("MinState=%v want LOADED", got.MinState)
	}
	if got.Changed {
		t.Fatal("Changed should be false when state matches")
	}
	if got.AllErrors != "" {
		t.Fatalf("AllErrors=%q", got.AllErrors)
	}
}

func TestCheckContentTreeStatus_Present_LoadedFromInitialIsChange(t *testing.T) {
	tc := newTestCtx(t)
	tc.subContentTreeStatus.items["ct-1"] = types.ContentTreeStatus{
		State: types.LOADED,
	}
	got := checkContentTreeStatus(tc.ctx, types.INITIAL, "ct-1")
	if !got.Changed {
		t.Fatal("Changed should be true on state advance")
	}
	if got.MinState != types.LOADED {
		t.Fatalf("MinState=%v want LOADED", got.MinState)
	}
}

func TestCheckContentTreeStatus_Error(t *testing.T) {
	tc := newTestCtx(t)
	cts := types.ContentTreeStatus{
		State: types.DOWNLOADING,
	}
	now := time.Now()
	cts.SetError("download failed", now)
	tc.subContentTreeStatus.items["ct-err"] = cts

	got := checkContentTreeStatus(tc.ctx, types.INITIAL, "ct-err")
	if got.AllErrors == "" {
		t.Fatal("expected error to be propagated")
	}
	if got.AllErrors == "" || got.ErrorTime.IsZero() {
		t.Fatalf("expected ErrorTime set, AllErrors=%q ErrorTime=%v",
			got.AllErrors, got.ErrorTime)
	}
	if !got.Changed {
		t.Fatal("Changed should be true on error path")
	}
}

// handleContentTreeStatusImpl: walks each BaseOsStatus referencing the
// updated content tree. We only verify the lookup → fanout works; the
// transitive baseOsHandleStatusUpdate body needs zboot seams (Phase 2).

func TestHandleContentTreeStatusImpl_FanoutSkipsNonBaseOs(t *testing.T) {
	tc := newTestCtx(t)
	// No BaseOsStatus references this content tree, so the body of
	// baseOsHandleStatusUpdateUUID is never reached. The function just
	// has to be a safe no-op in that case.
	cts := types.ContentTreeStatus{State: types.LOADED}
	handleContentTreeStatusImpl(tc.ctx, "ct-1", cts)
}
