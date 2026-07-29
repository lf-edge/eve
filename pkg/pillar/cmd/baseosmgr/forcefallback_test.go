// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"os"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestForceFallbackCounter_ReadAbsent(t *testing.T) {
	tc := newTestCtx(t)
	got, found := readForceFallbackCounter(tc.ctx)
	if found {
		t.Fatalf("expected found=false for absent file (got %d)", got)
	}
}

func TestForceFallbackCounter_WriteThenRead(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 7)
	got, found := readForceFallbackCounter(tc.ctx)
	if !found {
		t.Fatal("expected found=true after write")
	}
	if got != 7 {
		t.Fatalf("got %d want 7", got)
	}

	// File contents are decimal text, which is what the production code
	// promises.
	b, err := os.ReadFile(tc.ctx.paths.forceFallbackCounter)
	if err != nil {
		t.Fatalf("read counter file: %v", err)
	}
	if v := strings.TrimSpace(string(b)); v != "7" {
		t.Fatalf("file %q want %q", v, "7")
	}
}

func TestForceFallbackCounter_OverwritesExisting(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 3)
	writeForceFallbackCounter(tc.ctx, 4)
	got, found := readForceFallbackCounter(tc.ctx)
	if !found || got != 4 {
		t.Fatalf("got (%d, %v) want (4, true)", got, found)
	}
}

func TestForceFallbackCounter_GarbageContent(t *testing.T) {
	tc := newTestCtx(t)
	if err := os.WriteFile(tc.ctx.paths.forceFallbackCounter,
		[]byte("garbage"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// fileutils.ReadSavedCounter returns (0, false) on parse error.
	got, found := readForceFallbackCounter(tc.ctx)
	if found {
		t.Fatalf("expected found=false on garbage, got (%d, true)", got)
	}
}

// handleForceFallback: bumping ZedAgentStatus.ForceFallbackCounter is
// the controller's "switch back to previous image" knob. Production
// code requires curr=active and other=unused with non-empty ShortVersion;
// any mismatch is logged and ignored.

func TestHandleForceFallback_FirstObservationJustSavesCounter(t *testing.T) {
	tc := newTestCtx(t)
	st := types.ZedAgentStatus{ForceFallbackCounter: 5}
	handleForceFallback(tc.ctx, st)

	got, found := readForceFallbackCounter(tc.ctx)
	if !found || got != 5 {
		t.Fatalf("expected counter saved as 5, got (%d, %v)", got, found)
	}
	if tc.zb.setUpdating != 0 {
		t.Fatal("first observation must not flip partition state")
	}
}

func TestHandleForceFallback_NoChangeIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 7)
	st := types.ZedAgentStatus{ForceFallbackCounter: 7}
	handleForceFallback(tc.ctx, st)
	if tc.zb.setUpdating != 0 {
		t.Fatal("counter unchanged → must not flip partition state")
	}
}

func TestHandleForceFallback_MissingCurrentPartitionIgnored(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 1)
	// No ZbootStatus published for either partition.
	st := types.ZedAgentStatus{ForceFallbackCounter: 2}
	handleForceFallback(tc.ctx, st)
	if tc.zb.setUpdating != 0 {
		t.Fatal("must not flip without a current partition status")
	}
}

func TestHandleForceFallback_CurrentNotActiveIgnored(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 1)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "inprogress", ShortVersion: "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused", ShortVersion: "14.0",
	}
	handleForceFallback(tc.ctx, types.ZedAgentStatus{ForceFallbackCounter: 2})
	if tc.zb.setUpdating != 0 {
		t.Fatal("must not flip when curr is not active")
	}
}

func TestHandleForceFallback_OtherEmptyVersionIgnored(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 1)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused", ShortVersion: "",
	}
	handleForceFallback(tc.ctx, types.ZedAgentStatus{ForceFallbackCounter: 2})
	if tc.zb.setUpdating != 0 {
		t.Fatal("must not flip without a previous version on other")
	}
}

func TestHandleForceFallback_OtherNotUnusedIgnored(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 1)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	handleForceFallback(tc.ctx, types.ZedAgentStatus{ForceFallbackCounter: 2})
	if tc.zb.setUpdating != 0 {
		t.Fatal("must not flip when other is not unused")
	}
}

func TestHandleForceFallback_HappyPathFlipsAndPersists(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 1)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused", ShortVersion: "14.0",
	}
	handleForceFallback(tc.ctx, types.ZedAgentStatus{ForceFallbackCounter: 2})

	if tc.zb.setUpdating != 1 {
		t.Fatalf("expected SetOtherPartitionStateUpdating once, got %d",
			tc.zb.setUpdating)
	}
	got, found := readForceFallbackCounter(tc.ctx)
	if !found || got != 2 {
		t.Fatalf("counter not persisted: (%d, %v)", got, found)
	}
}

func TestHandleForceFallback_PublishesBaseOsStatusWhenMatched(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 1)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused", ShortVersion: "14.0",
	}
	tc.pubBaseOsStatus.items["IMGB"] = types.BaseOsStatus{
		ContentTreeUUID: "IMGB", BaseOsVersion: "14.0",
	}
	handleForceFallback(tc.ctx, types.ZedAgentStatus{ForceFallbackCounter: 2})

	got, _ := tc.pubBaseOsStatus.Get("IMGB")
	bst := got.(types.BaseOsStatus)
	if bst.PartitionLabel != "IMGB" {
		t.Fatalf("BaseOsStatus partition info not republished: %+v", bst)
	}
}

// handleZedAgentStatusImpl: thin wrapper around handleForceFallback.

func TestHandleZedAgentStatusImpl_DispatchesToForceFallback(t *testing.T) {
	tc := newTestCtx(t)
	st := types.ZedAgentStatus{ForceFallbackCounter: 9}
	handleZedAgentStatusImpl(tc.ctx, "global", st)
	got, found := readForceFallbackCounter(tc.ctx)
	if !found || got != 9 {
		t.Fatalf("expected counter saved, got (%d, %v)", got, found)
	}
}
