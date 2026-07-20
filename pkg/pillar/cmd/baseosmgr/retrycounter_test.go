// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// isImageInErrorState

func TestIsImageInErrorState_NoCurrentPartitionStatus(t *testing.T) {
	tc := newTestCtx(t)
	failed, st := isImageInErrorState(tc.ctx)
	if failed || st != nil {
		t.Fatalf("expected (false,nil), got (%v,%+v)", failed, st)
	}
}

func TestIsImageInErrorState_CurrentNotActive(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "inprogress",
	}
	failed, st := isImageInErrorState(tc.ctx)
	if failed || st != nil {
		t.Fatalf("got (%v,%+v)", failed, st)
	}
}

func TestIsImageInErrorState_OtherEmptyVersion(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", ShortVersion: "",
	}
	failed, _ := isImageInErrorState(tc.ctx)
	if failed {
		t.Fatal("empty other version → not in error state")
	}
}

func TestIsImageInErrorState_OtherNotInprogress(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused", ShortVersion: "14.0",
	}
	failed, _ := isImageInErrorState(tc.ctx)
	if failed {
		t.Fatal("other not inprogress → not in error state")
	}
}

func TestIsImageInErrorState_NoMatchingConfig(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	failed, _ := isImageInErrorState(tc.ctx)
	if failed {
		t.Fatal("no matching config → not in error state")
	}
}

func TestIsImageInErrorState_MatchingConfigNotActivate(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	tc.subBaseOsConfig.items["uuid-x"] = types.BaseOsConfig{
		BaseOsVersion: "14.0", Activate: false,
	}
	failed, _ := isImageInErrorState(tc.ctx)
	if failed {
		t.Fatal("Activate=false → not in error state")
	}
}

func TestIsImageInErrorState_HappyPath(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	tc.subBaseOsConfig.items["uuid-x"] = types.BaseOsConfig{
		BaseOsVersion: "14.0", Activate: true,
	}
	failed, st := isImageInErrorState(tc.ctx)
	if !failed || st == nil || st.PartitionLabel != "IMGB" {
		t.Fatalf("got (%v,%+v) want (true, IMGB)", failed, st)
	}
}

// handleUpdateRetryCounter: branch-by-branch.

func TestHandleUpdateRetryCounter_NoCurrentPartitionStatus(t *testing.T) {
	tc := newTestCtx(t)
	// No ZbootStatus published → warn-and-return.
	handleUpdateRetryCounter(tc.ctx, 1)
	if tc.zb.setUpdating != 0 {
		t.Fatal("must not flip other partition")
	}
}

func TestHandleUpdateRetryCounter_CurrentNotActiveNoChange(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "inprogress",
	}
	tc.ctx.configUpdateRetry = 5
	handleUpdateRetryCounter(tc.ctx, 5)
	// counter unchanged → silent return; no save
	if got := readSavedConfigRetryUpdateCounter(tc.ctx); got != 0 {
		t.Fatalf("must not save when no change, got %d", got)
	}
}

func TestHandleUpdateRetryCounter_CurrentNotActiveCounterChangeIsIgnored(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "inprogress",
	}
	tc.ctx.configUpdateRetry = 5
	handleUpdateRetryCounter(tc.ctx, 6)
	// Production code logs and returns without persisting; counter
	// in memory must NOT advance.
	if tc.ctx.configUpdateRetry != 5 {
		t.Fatalf("counter must not advance on inactive curr; got %d",
			tc.ctx.configUpdateRetry)
	}
}

func TestHandleUpdateRetryCounter_FailedImageBumpsAndReinstalls(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	tc.subBaseOsConfig.items["uuid-x"] = types.BaseOsConfig{
		ContentTreeUUID: "uuid-x", BaseOsVersion: "14.0", Activate: true,
	}
	tc.ctx.configUpdateRetry = 1

	handleUpdateRetryCounter(tc.ctx, 2)

	if tc.ctx.configUpdateRetry != 2 {
		t.Fatalf("expected counter advance to 2, got %d", tc.ctx.configUpdateRetry)
	}
	if got := readSavedConfigRetryUpdateCounter(tc.ctx); got != 2 {
		t.Fatalf("expected file=2, got %d", got)
	}
	if tc.zb.setUpdating != 1 {
		t.Fatalf("expected SetOtherPartitionStateUpdating once, got %d",
			tc.zb.setUpdating)
	}
}

func TestHandleUpdateRetryCounter_FailedImageNoChangeIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	tc.subBaseOsConfig.items["uuid-x"] = types.BaseOsConfig{
		BaseOsVersion: "14.0", Activate: true,
	}
	tc.ctx.configUpdateRetry = 5
	handleUpdateRetryCounter(tc.ctx, 5)
	if tc.zb.setUpdating != 0 {
		t.Fatal("no counter change → must not retrigger install")
	}
}

func TestHandleUpdateRetryCounter_HappyActivePathSavesAndPublishes(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused",
	}
	tc.ctx.configUpdateRetry = 0
	tc.ctx.currentUpdateRetry = 0

	handleUpdateRetryCounter(tc.ctx, 7)

	if tc.ctx.configUpdateRetry != 7 || tc.ctx.currentUpdateRetry != 7 {
		t.Fatalf("counters: cfg=%d cur=%d want 7,7",
			tc.ctx.configUpdateRetry, tc.ctx.currentUpdateRetry)
	}
	if got := readSavedConfigRetryUpdateCounter(tc.ctx); got != 7 {
		t.Fatalf("config file=%d want 7", got)
	}
	if got := readSavedCurrentRetryUpdateCounter(tc.ctx); got != 7 {
		t.Fatalf("current file=%d want 7", got)
	}
	got, err := tc.pubBaseOsMgrStatus.Get("global")
	if err != nil {
		t.Fatalf("BaseOSMgrStatus not published: %v", err)
	}
	if got.(types.BaseOSMgrStatus).CurrentRetryUpdateCounter != 7 {
		t.Fatalf("got %+v", got)
	}
}
