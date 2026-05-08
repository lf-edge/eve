// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/worker"

	uuid "github.com/satori/go.uuid"
)

// installWorker: the actual dd happens inside ctx.zboot.WriteToPartition,
// recorded by mockZboot.

func TestInstallWorker_NoTargetReturnsError(t *testing.T) {
	tc := newTestCtx(t)
	w := worker.Work{
		Key: "k1",
		Description: installWorkDescription{
			key:    "k1",
			ref:    "ref",
			target: "",
		},
	}
	res := installWorker(tc.ctx, w)
	if res.Error == nil {
		t.Fatal("expected error for empty target")
	}
	if len(tc.zb.writeCalls) != 0 {
		t.Fatalf("WriteToPartition must not be called: %v", tc.zb.writeCalls)
	}
}

func TestInstallWorker_HappyPath(t *testing.T) {
	tc := newTestCtx(t)
	w := worker.Work{
		Key: "k1",
		Description: installWorkDescription{
			key:    "k1",
			ref:    "sha256:abc",
			target: "IMGB",
		},
	}
	res := installWorker(tc.ctx, w)
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if got := tc.zb.writeCalls; len(got) != 1 || got[0] != "sha256:abc→IMGB" {
		t.Fatalf("WriteToPartition calls: %v", got)
	}
}

func TestInstallWorker_WriteErrorPropagates(t *testing.T) {
	tc := newTestCtx(t)
	tc.zb.writeErr = errBoom
	w := worker.Work{
		Key: "k1",
		Description: installWorkDescription{
			key:    "k1",
			ref:    "sha256:abc",
			target: "IMGB",
		},
	}
	res := installWorker(tc.ctx, w)
	if res.Error == nil {
		t.Fatal("expected error to propagate")
	}
	if res.ErrorTime.IsZero() {
		t.Fatal("ErrorTime should be set on error")
	}
}

// installDownloadedObject: drives the worker mock.

func TestInstallDownloadedObject_NotLoadedIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	cts := &types.ContentTreeStatus{State: types.DOWNLOADING}
	cid, _ := uuid.NewV4()
	changed, proceed, err := installDownloadedObject(tc.ctx, cid, "IMGB", cts)
	if changed || proceed || err != nil {
		t.Fatalf("got (%v,%v,%v) want (false,false,nil)", changed, proceed, err)
	}
}

func TestInstallDownloadedObject_NoFinalDirSetsErrorOnContentStatus(t *testing.T) {
	tc := newTestCtx(t)
	cid, _ := uuid.NewV4()
	cts := &types.ContentTreeStatus{
		State:       types.LOADED,
		ContentID:   cid,
		RelativeURL: "ref-x", // makes ReferenceID() non-empty
	}
	changed, proceed, err := installDownloadedObject(tc.ctx, cid, "", cts)
	if !changed || proceed || err == nil {
		t.Fatalf("got (%v,%v,%v) want (true,false,err)", changed, proceed, err)
	}
	if !cts.HasError() {
		t.Fatal("expected error stamped on cts")
	}
	if !strings.Contains(err.Error(), "final dir not set") {
		t.Fatalf("got %q", err.Error())
	}
}

func TestInstallDownloadedObject_FirstCallSubmitsWork(t *testing.T) {
	tc := newTestCtx(t)
	cid, _ := uuid.NewV4()
	cts := &types.ContentTreeStatus{
		State:       types.LOADED,
		ContentID:   cid,
		RelativeURL: "ref-x",
	}
	changed, proceed, err := installDownloadedObject(tc.ctx, cid, "IMGB", cts)
	if changed || proceed || err != nil {
		t.Fatalf("first call: got (%v,%v,%v) want (false,false,nil)",
			changed, proceed, err)
	}
	if got := len(tc.wk.submitted); got != 1 {
		t.Fatalf("expected one submitted work, got %d", got)
	}
	if tc.wk.submitted[0].Key != cid.String() {
		t.Fatalf("submitted Key = %q want %q",
			tc.wk.submitted[0].Key, cid.String())
	}
}

func TestInstallDownloadedObject_ResultPresentIndicatesProceed(t *testing.T) {
	tc := newTestCtx(t)
	cid, _ := uuid.NewV4()
	tc.wk.results[cid.String()] = &worker.WorkResult{Key: cid.String()}
	cts := &types.ContentTreeStatus{
		State:       types.LOADED,
		ContentID:   cid,
		RelativeURL: "ref-x",
	}
	changed, proceed, err := installDownloadedObject(tc.ctx, cid, "IMGB", cts)
	if !changed || !proceed || err != nil {
		t.Fatalf("got (%v,%v,%v) want (true,true,nil)", changed, proceed, err)
	}
}

func TestInstallDownloadedObject_ResultErrorPropagates(t *testing.T) {
	tc := newTestCtx(t)
	cid, _ := uuid.NewV4()
	tc.wk.results[cid.String()] = &worker.WorkResult{
		Key:       cid.String(),
		Error:     errBoom,
		ErrorTime: time.Now(),
	}
	cts := &types.ContentTreeStatus{
		State:       types.LOADED,
		ContentID:   cid,
		RelativeURL: "ref-x",
	}
	_, _, err := installDownloadedObject(tc.ctx, cid, "IMGB", cts)
	if err == nil {
		t.Fatal("expected error")
	}
}

// installDownloadedObjects: thin wrapper.

func TestInstallDownloadedObjects_MissingContentTreeReturnsError(t *testing.T) {
	tc := newTestCtx(t)
	_, _, err := installDownloadedObjects(tc.ctx, "uuid-x", "IMGB", "ct-absent")
	if err == nil {
		t.Fatal("expected error for absent content tree")
	}
}

func TestInstallDownloadedObjects_NotLoadedReturnsCleanly(t *testing.T) {
	tc := newTestCtx(t)
	tc.subContentTreeStatus.items["ct-1"] = types.ContentTreeStatus{
		State: types.DOWNLOADING,
	}
	changed, proceed, err := installDownloadedObjects(tc.ctx, "uuid-x", "IMGB", "ct-1")
	if changed || proceed || err != nil {
		t.Fatalf("got (%v,%v,%v) want (false,false,nil)", changed, proceed, err)
	}
}

// processInstallWorkResult: re-enters baseOsHandleStatusUpdateUUID with
// the saved key.

func TestProcessInstallWorkResult_NoConfigIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	res := worker.WorkResult{
		Key: "uuid-x",
		Description: installWorkDescription{
			key: "uuid-x",
		},
	}
	if err := processInstallWorkResult(tc.ctx, res); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

// AddWorkInstall: idempotent submit.

func TestAddWorkInstall_SubmitsThroughWorker(t *testing.T) {
	tc := newTestCtx(t)
	AddWorkInstall(tc.ctx, "k1", "ref-x", "IMGB")
	if got := len(tc.wk.submitted); got != 1 {
		t.Fatalf("expected one submission, got %d", got)
	}
	w := tc.wk.submitted[0]
	if w.Key != "k1" || w.Kind != workInstall {
		t.Fatalf("got %+v", w)
	}
	d := w.Description.(installWorkDescription)
	if d.ref != "ref-x" || d.target != "IMGB" {
		t.Fatalf("got %+v", d)
	}
}

func TestAddWorkInstall_TrySubmitErrorIsLoggedNotPanicking(t *testing.T) {
	tc := newTestCtx(t)
	tc.wk.submitErr = errBoom
	AddWorkInstall(tc.ctx, "k1", "ref-x", "IMGB")
	// No panic; submission still recorded so we can check we tried.
	if got := len(tc.wk.submitted); got != 1 {
		t.Fatalf("expected one attempt, got %d", got)
	}
}
