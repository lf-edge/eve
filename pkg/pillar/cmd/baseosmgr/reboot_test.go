// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// updateBaseOsStatusOnReboot: surface the previous boot's reboot reason
// onto whichever BaseOsStatus owns an other partition that just landed
// in inprogress (i.e. nodeagent rolled us back from a failed upgrade).

func TestUpdateBaseOsStatusOnReboot_OtherInprogressMatchingVersion(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
		ShortVersion:   "14.0",
	}
	// matching BaseOsStatus keyed by partLabel
	tc.pubBaseOsStatus.items["IMGB"] = types.BaseOsStatus{
		ContentTreeUUID: "IMGB",
		BaseOsVersion:   "14.0",
	}
	tc.ctx.rebootReason = "kernel panic"
	tc.ctx.rebootTime = time.Now()

	updateBaseOsStatusOnReboot(tc.ctx)

	got, _ := tc.pubBaseOsStatus.Get("IMGB")
	bst := got.(types.BaseOsStatus)
	if !bst.HasError() || !strings.Contains(bst.Error, "kernel panic") {
		t.Fatalf("expected reboot reason on BaseOsStatus, got %+v", bst)
	}
}

func TestUpdateBaseOsStatusOnReboot_OtherInprogressVersionMismatchSkipped(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
		ShortVersion:   "14.0",
	}
	tc.pubBaseOsStatus.items["IMGB"] = types.BaseOsStatus{
		ContentTreeUUID: "IMGB",
		BaseOsVersion:   "different",
	}
	tc.ctx.rebootReason = "kernel panic"

	updateBaseOsStatusOnReboot(tc.ctx)

	got, _ := tc.pubBaseOsStatus.Get("IMGB")
	bst := got.(types.BaseOsStatus)
	if bst.HasError() {
		t.Fatalf("must not stamp error on version mismatch: %+v", bst)
	}
}

func TestUpdateBaseOsStatusOnReboot_OtherNotInprogressIgnored(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
		ShortVersion:   "14.0",
	}
	tc.pubBaseOsStatus.items["IMGB"] = types.BaseOsStatus{
		ContentTreeUUID: "IMGB",
		BaseOsVersion:   "14.0",
	}
	tc.ctx.rebootReason = "kernel panic"

	updateBaseOsStatusOnReboot(tc.ctx)

	got, _ := tc.pubBaseOsStatus.Get("IMGB")
	bst := got.(types.BaseOsStatus)
	if bst.HasError() {
		t.Fatal("must not stamp error when other partition isn't inprogress")
	}
}

// handleOtherPartRebootReason: corner cases.

func TestHandleOtherPartRebootReason_RebootedFromCurrentImageIsNoop(t *testing.T) {
	tc := newTestCtx(t)
	// rebootImage matches current partition → we did NOT roll back.
	tc.ctx.rebootImage = "IMGA"
	tc.ctx.rebootReason = "kernel panic"
	st := types.BaseOsStatus{}
	handleOtherPartRebootReason(tc.ctx, &st)
	if st.HasError() {
		t.Fatalf("expected no error: %q", st.Error)
	}
}

func TestHandleOtherPartRebootReason_EmptyReasonSynthesizesPowerFailMessage(t *testing.T) {
	tc := newTestCtx(t)
	tc.ctx.rebootImage = "IMGB" // not current
	tc.ctx.rebootReason = ""    // unknown
	tc.ctx.rebootTime = time.Now()
	st := types.BaseOsStatus{}
	handleOtherPartRebootReason(tc.ctx, &st)
	if !st.HasError() {
		t.Fatal("expected synthesized error")
	}
	if !strings.Contains(st.Error, "power failure") {
		t.Fatalf("got %q want substring 'power failure'", st.Error)
	}
}

// handleNodeAgentStatusImpl: copies fields from NodeAgentStatus and runs
// updateBaseOsStatusOnReboot.

func TestHandleNodeAgentStatusImpl_LatchesAndDispatches(t *testing.T) {
	tc := newTestCtx(t)
	rebootTime := time.Now()
	st := types.NodeAgentStatus{
		RebootReason: "watchdog",
		RebootImage:  "IMGB",
		RebootTime:   rebootTime,
	}
	handleNodeAgentStatusImpl(tc.ctx, "global", st)
	if tc.ctx.rebootReason != "watchdog" || tc.ctx.rebootImage != "IMGB" ||
		!tc.ctx.rebootTime.Equal(rebootTime) {
		t.Fatalf("ctx fields not latched: %+v", tc.ctx)
	}
}

func TestHandleNodeAgentStatusImpl_StampsErrorWhenOtherInprogress(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
		ShortVersion:   "14.0",
	}
	tc.pubBaseOsStatus.items["IMGB"] = types.BaseOsStatus{
		ContentTreeUUID: "IMGB",
		BaseOsVersion:   "14.0",
	}
	st := types.NodeAgentStatus{
		RebootReason: "BOOT_REASON_FALLBACK",
		RebootImage:  "IMGB",
		RebootTime:   time.Now(),
	}
	handleNodeAgentStatusImpl(tc.ctx, "global", st)

	got, _ := tc.pubBaseOsStatus.Get("IMGB")
	bst := got.(types.BaseOsStatus)
	if !bst.HasError() {
		t.Fatalf("expected error stamped: %+v", bst)
	}
}
