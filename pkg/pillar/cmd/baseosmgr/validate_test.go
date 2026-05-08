// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// validatePartition: refuse if other partition is inprogress with the
// same version (i.e. the previous attempt at this exact upgrade
// failed and is pending fallback).

func TestValidatePartition_OtherInprogressSameVersionRejected(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
		ShortVersion:   "13.4.0",
	}
	tc.ctx.rebootReason = "kernel panic"
	cfg := types.BaseOsConfig{BaseOsVersion: "13.4.0", ContentTreeUUID: "uuid-x"}
	st := types.BaseOsStatus{ContentTreeUUID: "uuid-x"}

	changed, proceed := validatePartition(tc.ctx, cfg, &st)
	if !changed || proceed {
		t.Fatalf("got changed=%v proceed=%v want true,false", changed, proceed)
	}
	if st.Error == "" {
		t.Fatal("expected reboot reason copied onto BaseOsStatus.Error")
	}
}

func TestValidatePartition_OtherInprogressDifferentVersionAccepted(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "inprogress",
		ShortVersion:   "12.0.0", // not the version we're being asked to install
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "13.4.0"}
	st := types.BaseOsStatus{}
	changed, proceed := validatePartition(tc.ctx, cfg, &st)
	if changed || !proceed {
		t.Fatalf("got changed=%v proceed=%v want false,true", changed, proceed)
	}
}

func TestValidatePartition_OtherUnusedAccepted(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "13.4.0"}
	st := types.BaseOsStatus{}
	if _, proceed := validatePartition(tc.ctx, cfg, &st); !proceed {
		t.Fatal("expected proceed=true")
	}
}

// validateAndAssignPartition: refuse if curr=inprogress (we're still
// testing) or if other=active (we're still in fallback window for some
// other upgrade); otherwise assign other partition when needed.

func TestValidateAndAssignPartition_CurrentInprogressMarksTooEarly(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "inprogress",
		ShortVersion:   "13.4.0",
	}
	tc.zb.parts["IMGA"].state = "inprogress"
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", Activate: true}
	st := types.BaseOsStatus{}

	changed, proceed := validateAndAssignPartition(tc.ctx, cfg, &st)
	if !changed || proceed {
		t.Fatalf("got changed=%v proceed=%v want true,false", changed, proceed)
	}
	if !st.TooEarly {
		t.Fatal("TooEarly should be set")
	}
}

func TestValidateAndAssignPartition_OtherActiveMarksTooEarly(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
	}
	// Other partition somehow active too — defensive precondition.
	tc.zb.parts["IMGB"].state = "active"
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "active",
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", Activate: true}
	st := types.BaseOsStatus{}
	_, proceed := validateAndAssignPartition(tc.ctx, cfg, &st)
	if proceed || !st.TooEarly {
		t.Fatalf("got proceed=%v TooEarly=%v want false,true", proceed, st.TooEarly)
	}
}

func TestValidateAndAssignPartition_FreshAssignmentToOther(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel:   "IMGB",
		PartitionState:   "unused",
		PartitionDevname: "/dev/sda4",
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", Activate: true}
	st := types.BaseOsStatus{} // no PartitionLabel yet

	changed, proceed := validateAndAssignPartition(tc.ctx, cfg, &st)
	if !changed || !proceed {
		t.Fatalf("got changed=%v proceed=%v want true,true", changed, proceed)
	}
	if st.PartitionLabel != "IMGB" || st.PartitionState != "unused" ||
		st.PartitionDevice != "/dev/sda4" {
		t.Fatalf("unexpected assignment: %+v", st)
	}
}

func TestValidateAndAssignPartition_InactiveConfigDoesNotAssign(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", Activate: false}
	st := types.BaseOsStatus{}
	changed, proceed := validateAndAssignPartition(tc.ctx, cfg, &st)
	if !proceed {
		t.Fatal("should proceed when no preconditions hit")
	}
	if changed || st.PartitionLabel != "" {
		t.Fatalf("Activate=false should not assign: %+v changed=%v",
			st, changed)
	}
}

func TestValidateAndAssignPartition_AlreadyAssignedNoChange(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGA"] = types.ZbootStatus{
		PartitionLabel: "IMGA",
		PartitionState: "active",
	}
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		PartitionState: "unused",
	}
	cfg := types.BaseOsConfig{BaseOsVersion: "14.0", Activate: true}
	st := types.BaseOsStatus{PartitionLabel: "IMGB"} // already assigned
	changed, proceed := validateAndAssignPartition(tc.ctx, cfg, &st)
	if !proceed {
		t.Fatal("should proceed")
	}
	if changed {
		t.Fatal("no change expected when already assigned")
	}
}
