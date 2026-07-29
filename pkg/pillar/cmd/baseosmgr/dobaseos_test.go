// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// doBaseOsStatusUpdate: branch coverage for the early-return paths
// that don't require a fully wired install pipeline.

func TestDoBaseOsStatusUpdate_ContentTreeError(t *testing.T) {
	tc := newTestCtx(t)
	cts := types.ContentTreeStatus{}
	cts.SetError("download failed", time.Now())
	tc.subContentTreeStatus.items["uuid-x"] = cts
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		ShortVersion:   "13.4",
	}

	cfg := types.BaseOsConfig{
		BaseOsVersion:   "14.0",
		ContentTreeUUID: "uuid-x",
		Activate:        true,
	}
	st := types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	changed := doBaseOsStatusUpdate(tc.ctx, "uuid-x", cfg, &st)
	if !changed || !st.HasError() {
		t.Fatalf("expected error propagation: changed=%v err=%q",
			changed, st.Error)
	}
}

func TestDoBaseOsStatusUpdate_AlreadyOnCurrentVersion(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
		ShortVersion:   "13.4.0",
	}
	tc.subContentTreeStatus.items["uuid-x"] = types.ContentTreeStatus{
		State: types.LOADED,
	}

	cfg := types.BaseOsConfig{
		BaseOsVersion:   "13.4.0",
		ContentTreeUUID: "uuid-x",
		Activate:        true,
	}
	st := types.BaseOsStatus{
		BaseOsVersion:   "13.4.0",
		ContentTreeUUID: "uuid-x",
	}
	changed := doBaseOsStatusUpdate(tc.ctx, "uuid-x", cfg, &st)
	if !changed || st.State != types.INSTALLED || !st.Activated {
		t.Fatalf("unexpected: changed=%v state=%v activated=%v",
			changed, st.State, st.Activated)
	}
	if st.PartitionLabel != "IMGA" {
		t.Fatalf("expected IMGA, got %q", st.PartitionLabel)
	}
}

func TestDoBaseOsStatusUpdate_AlreadyInOtherPartition_DeactivatedPath(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
		ShortVersion:   "13.4",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
		ShortVersion:   "14.0",
	}
	tc.subContentTreeStatus.items["uuid-x"] = types.ContentTreeStatus{
		State: types.LOADED,
	}

	// Activate=false: same version already on other partition, just
	// reflect the partition info; no install/activate path.
	cfg := types.BaseOsConfig{
		BaseOsVersion:   "14.0",
		ContentTreeUUID: "uuid-x",
		Activate:        false,
	}
	st := types.BaseOsStatus{
		BaseOsVersion:   "14.0",
		ContentTreeUUID: "uuid-x",
	}
	if !doBaseOsStatusUpdate(tc.ctx, "uuid-x", cfg, &st) {
		t.Fatal("expected change")
	}
	if st.PartitionLabel != "IMGB" {
		t.Fatalf("expected IMGB latched, got %q", st.PartitionLabel)
	}
	// Should not have triggered any zboot mutations.
	if tc.zb.setUpdating != 0 || tc.zb.setUnused != 0 {
		t.Fatalf("unexpected zboot writes: updating=%d unused=%d",
			tc.zb.setUpdating, tc.zb.setUnused)
	}
}

func TestDoBaseOsStatusUpdate_RejectsKubeMixSwitch(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13-kvm",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused",
	}
	tc.subContentTreeStatus.items["uuid-x"] = types.ContentTreeStatus{
		State: types.LOADED,
	}
	tc.currentIsKube = false                         // currently kvm
	tc.versionIsKube = map[string]bool{"14-k": true} // upgrade is EVE-k

	cfg := types.BaseOsConfig{
		BaseOsVersion:   "14-k",
		ContentTreeUUID: "uuid-x",
		Activate:        true,
	}
	st := types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	changed := doBaseOsStatusUpdate(tc.ctx, "uuid-x", cfg, &st)
	if !changed || !st.HasError() {
		t.Fatalf("expected reject: changed=%v err=%q", changed, st.Error)
	}
	if !strings.Contains(st.Error, "EVE-k") {
		t.Fatalf("error text doesn't mention EVE-k: %q", st.Error)
	}
}

func TestDoBaseOsStatusUpdate_KubePersonalityErrorIsLogged(t *testing.T) {
	// IsVersionHVTypeKube returning an error must NOT block the upgrade
	// — the production code logs a warning and continues. The volume
	// state is incomplete, so the install path no-ops.
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "unused",
	}
	tc.versionIsKubeErr = errBoom
	cfg := types.BaseOsConfig{
		BaseOsVersion: "14", ContentTreeUUID: "uuid-x", Activate: true,
	}
	st := types.BaseOsStatus{ContentTreeUUID: "uuid-x"}
	// No content-tree status: doBaseOsInstall → checkBaseOsVolumeStatus
	// returns done=false, so doBaseOsStatusUpdate should not error.
	if doBaseOsStatusUpdate(tc.ctx, "uuid-x", cfg, &st) && st.HasError() {
		t.Fatalf("warning-only branch must not set error: %q", st.Error)
	}
}

// doBaseOsActivate: precondition checks before the install worker.

func TestDoBaseOsActivate_NotOtherPartitionIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", ContentTreeUUID: "uuid-x"}
	st := types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
		PartitionLabel:  "IMGA", // current partition; not "other"
	}
	if doBaseOsActivate(tc.ctx, "uuid-x", cfg, &st) {
		t.Fatal("expected no-op when label != other partition")
	}
}

func TestDoBaseOsActivate_PartitionStatusMissingIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	// Don't publish ZbootStatus for IMGB.
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", ContentTreeUUID: "uuid-x"}
	st := types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
		PartitionLabel:  "IMGB",
	}
	if doBaseOsActivate(tc.ctx, "uuid-x", cfg, &st) {
		t.Fatal("expected no-op when no IMGB ZbootStatus")
	}
}

func TestDoBaseOsActivate_BadPartitionStateErrors(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "active", // not unused/inprogress/updating
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", ContentTreeUUID: "uuid-x"}
	st := types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
		PartitionLabel:  "IMGB",
	}
	if !doBaseOsActivate(tc.ctx, "uuid-x", cfg, &st) || !st.HasError() {
		t.Fatalf("expected error, st=%+v", st)
	}
	if !strings.Contains(st.Error, "Wrong partition state") {
		t.Fatalf("unexpected error text: %q", st.Error)
	}
}

func TestDoBaseOsActivate_ContentTreeMissingErrors(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	// No ContentTreeStatus seeded.
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", ContentTreeUUID: "uuid-x"}
	st := types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
		PartitionLabel:  "IMGB",
	}
	if !doBaseOsActivate(tc.ctx, "uuid-x", cfg, &st) || !st.HasError() {
		t.Fatalf("expected error: %+v", st)
	}
}

func TestDoBaseOsActivate_ImageLargerThanPartition(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	tc.zb.parts["IMGB"].sizeB = 100
	tc.subContentTreeStatus.items["uuid-x"] = types.ContentTreeStatus{
		State:           types.LOADED,
		MaxDownloadSize: 1 << 30,
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", ContentTreeUUID: "uuid-x"}
	st := types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
		PartitionLabel:  "IMGB",
	}
	changed := doBaseOsActivate(tc.ctx, "uuid-x", cfg, &st)
	if !changed || !st.HasError() {
		t.Fatalf("expected size error: %+v", st)
	}
	if !strings.Contains(st.Error, "greater than partition size") {
		t.Fatalf("unexpected error text: %q", st.Error)
	}
}

// doBaseOsInactivate: still a comment-only no-op that returns true.

func TestDoBaseOsInactivate_AlwaysReturnsTrue(t *testing.T) {
	st := types.BaseOsStatus{Activated: true}
	if !doBaseOsInactivate("uuid-x", &st) {
		t.Fatal("expected true")
	}
}

// doBaseOsRemove / doBaseOsUninstall

func TestDoBaseOsUninstall_OtherActiveCannotMarkUnused(t *testing.T) {
	tc := newTestCtx(t)
	// Other partition state inprogress, but current partition NOT
	// active — production code logs a warning and refuses to mark
	// unused; PartitionLabel is still cleared.
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "inprogress",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB", PartitionState: "inprogress", ShortVersion: "14.0",
	}
	tc.zb.parts["IMGA"].state = "inprogress"
	st := types.BaseOsStatus{
		BaseOsVersion:   "14.0",
		ContentTreeUUID: "uuid-x",
		PartitionLabel:  "IMGB",
	}
	changed, _ := doBaseOsUninstall(tc.ctx, "uuid-x", &st)
	if !changed || tc.zb.setUnused != 0 {
		t.Fatalf("must clear PartitionLabel without writing zboot: changed=%v setUnused=%d",
			changed, tc.zb.setUnused)
	}
	if st.PartitionLabel != "" {
		t.Fatalf("PartitionLabel should be cleared, got %q", st.PartitionLabel)
	}
}

func TestDoBaseOsUninstall_NoPartitionLabelButContentTreeStillThere(t *testing.T) {
	tc := newTestCtx(t)
	tc.subContentTreeStatus.items["uuid-x"] = types.ContentTreeStatus{}
	st := types.BaseOsStatus{
		BaseOsVersion:   "14.0",
		ContentTreeUUID: "uuid-x",
	}
	changed, del := doBaseOsUninstall(tc.ctx, "uuid-x", &st)
	if changed {
		t.Fatal("nothing to change without PartitionLabel and with content present")
	}
	if del {
		t.Fatal("must wait for volumemgr purge")
	}
}

func TestDoBaseOsUninstall_AllRemovedDeletes(t *testing.T) {
	tc := newTestCtx(t)
	// No content tree, no partition label → ready to delete.
	st := types.BaseOsStatus{
		BaseOsVersion:   "14.0",
		ContentTreeUUID: "uuid-x",
	}
	_, del := doBaseOsUninstall(tc.ctx, "uuid-x", &st)
	if !del {
		t.Fatal("expected del=true when nothing left to clean up")
	}
}

func TestRemoveBaseOsStatus_PublishesAndDeletes(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubBaseOsStatus.items["uuid-x"] = types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
	}
	removeBaseOsStatus(tc.ctx, "uuid-x")
	if _, err := tc.pubBaseOsStatus.Get("uuid-x"); err == nil {
		t.Fatal("expected entry to be removed")
	}
}

func TestRemoveBaseOsStatus_NoStatusIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	removeBaseOsStatus(tc.ctx, "absent")
}

// baseOsHandleStatusUpdate end-to-end: simplest path is the
// "already-on-current" early return which exercises the publish.

func TestBaseOsHandleStatusUpdate_PublishesWhenChanged(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA", PartitionState: "active", ShortVersion: "13.4.0",
		CurrentPartition: true,
	}
	tc.subContentTreeStatus.items["uuid-x"] = types.ContentTreeStatus{
		State: types.LOADED,
	}
	cfg := types.BaseOsConfig{
		BaseOsVersion:   "13.4.0",
		ContentTreeUUID: "uuid-x",
		Activate:        true,
	}
	st := types.BaseOsStatus{
		BaseOsVersion:   "13.4.0",
		ContentTreeUUID: "uuid-x",
	}
	baseOsHandleStatusUpdate(tc.ctx, &cfg, &st)

	got, err := tc.pubBaseOsStatus.Get("uuid-x")
	if err != nil {
		t.Fatalf("expected publish, got %v", err)
	}
	pst := got.(types.BaseOsStatus)
	if !pst.Activated || pst.State != types.INSTALLED {
		t.Fatalf("got %+v", pst)
	}
}

// handleBaseOsConfigCreate: validates, then publishes BaseOsStatus
// (with or without error) and runs the state machine.

func TestHandleBaseOsConfigCreate_EmptyContentTreeRejected(t *testing.T) {
	tc := newTestCtx(t)
	cfg := types.BaseOsConfig{BaseOsVersion: "13.4", ContentTreeUUID: ""}
	handleBaseOsConfigCreate(tc.ctx, "k", cfg)
	got, err := tc.pubBaseOsStatus.Get("")
	if err != nil {
		t.Fatalf("expected error-bearing publication, got %v", err)
	}
	st := got.(types.BaseOsStatus)
	if !st.HasError() {
		t.Fatal("expected error set")
	}
}

func TestHandleBaseOsConfigModify_UnknownStatusIgnored(t *testing.T) {
	tc := newTestCtx(t)
	cfg := types.BaseOsConfig{BaseOsVersion: "13.4", ContentTreeUUID: "uuid-x"}
	// No corresponding BaseOsStatus published yet.
	handleBaseOsConfigModify(tc.ctx, "uuid-x", cfg, nil)
	if got := len(tc.pubBaseOsStatus.items); got != 0 {
		t.Fatalf("expected no publish, got %d entries", got)
	}
}

// baseOsHandleStatusUpdateUUID: the dispatcher used by the worker
// callback / volumemgr fanout.

func TestBaseOsHandleStatusUpdateUUID_NoConfigIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubBaseOsStatus.items["uuid-x"] = types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
	}
	baseOsHandleStatusUpdateUUID(tc.ctx, "uuid-x")
}

func TestBaseOsHandleStatusUpdateUUID_NoStatusIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	tc.subBaseOsConfig.items["uuid-x"] = types.BaseOsConfig{
		ContentTreeUUID: "uuid-x", BaseOsVersion: "14.0",
	}
	baseOsHandleStatusUpdateUUID(tc.ctx, "uuid-x")
}

func TestBaseOsHandleStatusUpdateUUID_NoContentTreeStatusIsLoggedOnly(t *testing.T) {
	tc := newTestCtx(t)
	tc.subBaseOsConfig.items["uuid-x"] = types.BaseOsConfig{
		ContentTreeUUID: "uuid-x",
	}
	tc.pubBaseOsStatus.items["uuid-x"] = types.BaseOsStatus{
		ContentTreeUUID: "uuid-x",
	}
	// No ContentTreeStatus seeded → early return after error log.
	baseOsHandleStatusUpdateUUID(tc.ctx, "uuid-x")
}
