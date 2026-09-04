// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func repackableApp() *types.AppInstanceStatus {
	status := &types.AppInstanceStatus{
		DisplayName:      "vpp",
		State:            types.RUNNING,
		Activated:        true,
		PlacementQuality: types.CPUPlacementQualityNeedsRepack,
		BootTime:         time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	return status
}

// A workload that would be better placed after a repack must reach the
// controller -- otherwise the whole "the device says which apps are affected,
// the controller decides whether a restart is worth it" loop has no input.
func TestCPUPlacementAdvisory_ReportsNeedsRepack(t *testing.T) {
	errInfo := cpuPlacementAdvisory(repackableApp())
	if errInfo == nil {
		t.Fatal("a workload needing a repack must be reported")
	}
	if errInfo.ErrorCode != types.ErrorCodeCPUPlacementNeedsRepack {
		t.Errorf("error_code %q, want %q", errInfo.ErrorCode,
			types.ErrorCodeCPUPlacementNeedsRepack)
	}
	if errInfo.Severity != info.Severity_SEVERITY_WARNING {
		t.Errorf("severity %v, want WARNING: a sub-optimally placed workload is "+
			"running normally and must not be reported as failed", errInfo.Severity)
	}
	if errInfo.Timestamp == nil {
		t.Error("an ErrorInfo without a timestamp is dropped on the wire")
	}
}

// The advisory must not make the app look broken: it is carried alongside the
// app's real error state, never inside it, so nothing that tests HasError()
// starts treating the workload as failed.
func TestCPUPlacementAdvisory_DoesNotFailTheApp(t *testing.T) {
	status := repackableApp()

	if errInfo := cpuPlacementAdvisory(status); errInfo == nil {
		t.Fatal("expected an advisory")
	}
	if status.HasError() {
		t.Error("the advisory must not put the app into an error state")
	}
	if status.State != types.RUNNING {
		t.Errorf("state %v, want RUNNING", status.State)
	}
}

// Everything else is silent: an optimally placed workload, one whose placement
// was never evaluated, and one that is not pinned at all.
func TestCPUPlacementAdvisory_SilentOtherwise(t *testing.T) {
	for _, quality := range []types.CPUPlacementQuality{
		types.CPUPlacementQualityUnspecified,
		types.CPUPlacementQualityOptimal,
	} {
		status := repackableApp()
		status.PlacementQuality = quality
		if errInfo := cpuPlacementAdvisory(status); errInfo != nil {
			t.Errorf("quality %v must not be reported, got %+v", quality, errInfo)
		}
	}
}

// The timestamp has to be stable, or every periodic info message would look
// like a fresh occurrence of the same condition.
func TestCPUPlacementAdvisory_TimestampIsStable(t *testing.T) {
	status := repackableApp()
	first := cpuPlacementAdvisory(status)
	second := cpuPlacementAdvisory(status)
	if !first.Timestamp.AsTime().Equal(second.Timestamp.AsTime()) {
		t.Errorf("timestamp moved between reports: %v then %v",
			first.Timestamp.AsTime(), second.Timestamp.AsTime())
	}
	if !first.Timestamp.AsTime().Equal(status.BootTime) {
		t.Errorf("timestamp %v, want the boot the placement was decided at (%v)",
			first.Timestamp.AsTime(), status.BootTime)
	}
}

// TestCPUPlacementAdvisory_RidesAlongsideARealAppError is the premise of the whole
// advisory design: a workload whose placement is merely improvable must never be
// torn down for it, so the advisory is a second entry on ZInfoApp.app_err rather
// than a replacement for the app's real error.
//
// The append itself lives in PublishAppInfoToZedCloud, which needs the full
// zedagentContext (app IPs, network instances, the send queue) to call; this
// covers the two producers whose output it concatenates -- that both yield an
// entry for the same status, and that each keeps its own severity and code.
func TestCPUPlacementAdvisory_RidesAlongsideARealAppError(t *testing.T) {
	status := repackableApp()
	status.SetErrorWithSourceAndDescription(types.ErrorDescription{
		Error:         "domain failed to attach a passthrough device",
		ErrorCode:     "domain.adapter.failed",
		ErrorSeverity: types.ErrorSeverityError,
		ErrorTime:     time.Date(2026, 8, 8, 12, 5, 0, 0, time.UTC),
	}, types.DomainStatus{})

	appErr := status.ErrorAndTimeWithSource.ErrorDescription.ToProto()
	advisory := cpuPlacementAdvisory(status)
	if appErr == nil {
		t.Fatal("the app's own error must still be reported")
	}
	if advisory == nil {
		t.Fatal("an app that already has an error must still get the placement " +
			"advisory: suppressing it loses the only signal a repack is possible")
	}

	if appErr.Severity != info.Severity_SEVERITY_ERROR {
		t.Errorf("the app's own error was reported as %v, want ERROR: the advisory "+
			"must not downgrade a genuine failure", appErr.Severity)
	}
	if advisory.Severity != info.Severity_SEVERITY_WARNING {
		t.Errorf("advisory severity %v, want WARNING", advisory.Severity)
	}
	if appErr.ErrorCode == advisory.ErrorCode {
		t.Errorf("both entries carry error_code %q, so a controller cannot tell "+
			"the failure from the advisory", appErr.ErrorCode)
	}
	if advisory.ErrorCode != types.ErrorCodeCPUPlacementNeedsRepack {
		t.Errorf("advisory error_code %q, want %q", advisory.ErrorCode,
			types.ErrorCodeCPUPlacementNeedsRepack)
	}
}
