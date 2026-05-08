// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// checkInstalledVersion: read ShortVersion back from the partition mirror
// and compare against the BaseOsStatus.BaseOsVersion the controller asked
// for. Mismatch returns an error string that triggers a rollback in
// doBaseOsActivate.

func TestCheckInstalledVersion_NoPartitionLabel(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{BaseOsVersion: "14.0"}
	got := checkInstalledVersion(tc.ctx, st)
	if !strings.Contains(got, "invalid partition") {
		t.Fatalf("got %q", got)
	}
}

func TestCheckInstalledVersion_Match(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		ShortVersion:   "14.0",
	}
	st := types.BaseOsStatus{BaseOsVersion: "14.0", PartitionLabel: "IMGB"}
	if got := checkInstalledVersion(tc.ctx, st); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestCheckInstalledVersion_Mismatch(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubZbootStatus.items["IMGB"] = types.ZbootStatus{
		PartitionLabel: "IMGB",
		ShortVersion:   "13.4.0", // configured BaseOsVersion below differs
	}
	st := types.BaseOsStatus{BaseOsVersion: "14.0", PartitionLabel: "IMGB"}
	got := checkInstalledVersion(tc.ctx, st)
	if !strings.Contains(got, "image name not match") {
		t.Fatalf("got %q", got)
	}
}

func TestCheckInstalledVersion_PartitionStatusAbsentMismatchBecauseEmpty(t *testing.T) {
	// No ZbootStatus published; ShortVersion treated as "" → mismatch.
	tc := newTestCtx(t)
	st := types.BaseOsStatus{BaseOsVersion: "14.0", PartitionLabel: "IMGB"}
	got := checkInstalledVersion(tc.ctx, st)
	if !strings.Contains(got, "image name not match") {
		t.Fatalf("got %q", got)
	}
}
