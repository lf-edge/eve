// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func repackableApp() *types.AppInstanceStatus {
	status := &types.AppInstanceStatus{
		DisplayName:        "vpp",
		State:              types.RUNNING,
		Activated:          true,
		CPUPlacementStatus: types.CPUPlacementStatusRepackAdvised,
		BootTime:           time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	return status
}

// What the controller acts on is domainmgr's verdict, with a wait and a
// repack membership laid over it.
func TestCPUPlacementStatus(t *testing.T) {
	wait := types.CPUWait{Holders: []string{"n8-a"}, Since: time.Now()}
	for _, tt := range []struct {
		name   string
		status *types.AppInstanceStatus
		want   types.CPUPlacementStatus
	}{
		{"no CPU request", &types.AppInstanceStatus{},
			types.CPUPlacementStatusUnspecified},
		{"placed", &types.AppInstanceStatus{CPUPlacementStatus: types.CPUPlacementStatusPlaced},
			types.CPUPlacementStatusPlaced},
		{"placed worse than planned", repackableApp(),
			types.CPUPlacementStatusRepackAdvised},
		{"placed well, in another workload's way", &types.AppInstanceStatus{
			CPUPlacementStatus: types.CPUPlacementStatusPlaced, RepackFor: []string{"n6-a"}},
			types.CPUPlacementStatusRepackAdvised},
		{"waiting for its planned CPUs", &types.AppInstanceStatus{CPUWait: wait},
			types.CPUPlacementStatusWaiting},
		{"refused", &types.AppInstanceStatus{CPUPlacementStatus: types.CPUPlacementStatusNeedsRepack},
			types.CPUPlacementStatusNeedsRepack},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := cpuPlacementStatus(tt.status); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// The device's enums go on the wire as numbers, so each value must be the
// wire value of the same name.
func TestCPUPlacementEnumsMatchTheWire(t *testing.T) {
	for device, wire := range map[types.CPUPlacementStatus]info.CPUPlacementStatus{
		types.CPUPlacementStatusUnspecified:          info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_UNSPECIFIED,
		types.CPUPlacementStatusPlaced:               info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_PLACED,
		types.CPUPlacementStatusWaiting:              info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_WAITING,
		types.CPUPlacementStatusRepackAdvised:        info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_REPACK_ADVISED,
		types.CPUPlacementStatusNeedsRepack:          info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_NEEDS_REPACK,
		types.CPUPlacementStatusInsufficient:         info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_INSUFFICIENT,
		types.CPUPlacementStatusPolicyInvalid:        info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_POLICY_INVALID,
		types.CPUPlacementStatusOddVCPU:              info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_ODD_VCPU,
		types.CPUPlacementStatusTopologyUnsupported:  info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_TOPOLOGY_UNSUPPORTED,
		types.CPUPlacementStatusIsolationUnavailable: info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_ISOLATION_UNAVAILABLE,
	} {
		if info.CPUPlacementStatus(device) != wire {
			t.Errorf("%v is %d on the device and %d (%v) on the wire",
				device, device, wire, wire)
		}
	}
	for device, wire := range map[types.CPUPoolIssue]info.CPUPoolIssue{
		types.CPUPoolIssueUnspecified:  info.CPUPoolIssue_CPU_POOL_ISSUE_UNSPECIFIED,
		types.CPUPoolIssueReservedCPUs: info.CPUPoolIssue_CPU_POOL_ISSUE_RESERVED_CPUS,
		types.CPUPoolIssuePartialCore:  info.CPUPoolIssue_CPU_POOL_ISSUE_PARTIAL_CORE,
	} {
		if info.CPUPoolIssue(device) != wire {
			t.Errorf("pool issue %d on the device is %d (%v) on the wire", device, wire, wire)
		}
	}
}

// A workload that would be better placed after a repack must reach the
// controller -- otherwise the whole "the device says which apps are affected,
// the controller decides whether a restart is worth it" loop has no input.
func TestCPUPlacementAdvisory_ReportsAWorsePlacement(t *testing.T) {
	errInfo := cpuPlacementAdvisory(repackableApp())
	if errInfo == nil {
		t.Fatal("a workload needing a repack must be reported")
	}
	if !strings.Contains(errInfo.Description, "worse than") {
		t.Errorf("description must say its placement is worse than it could be: %q",
			errInfo.Description)
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

// Everything else is silent: an optimally placed workload, one without a CPU
// request, and a refused one, whose text is the app's own error.
func TestCPUPlacementAdvisory_SilentOtherwise(t *testing.T) {
	for _, verdict := range []types.CPUPlacementStatus{
		types.CPUPlacementStatusUnspecified,
		types.CPUPlacementStatusPlaced,
		types.CPUPlacementStatusNeedsRepack,
		types.CPUPlacementStatusInsufficient,
	} {
		status := repackableApp()
		status.CPUPlacementStatus = verdict
		if errInfo := cpuPlacementAdvisory(status); errInfo != nil {
			t.Errorf("%v must not get an advisory, got %+v", verdict, errInfo)
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
// entry for the same status, and that each keeps its own severity.
func TestCPUPlacementAdvisory_RidesAlongsideARealAppError(t *testing.T) {
	status := repackableApp()
	status.SetErrorWithSourceAndDescription(types.ErrorDescription{
		Error:         "domain failed to attach a passthrough device",
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
	if got := cpuPlacementStatus(status); got != types.CPUPlacementStatusRepackAdvised {
		t.Errorf("status %v, want %v: the app's error must not hide that it is "+
			"part of a repack", got, types.CPUPlacementStatusRepackAdvised)
	}
}

// A repack member is placed well itself but stands in another workload's way.
// It must still be reported as REPACK_ADVISED, so the controller's repack
// restarts it with the workload it makes room for, but not with the wording
// that says its own placement is bad.
func TestCPUPlacementAdvisory_ReportsRepackMember(t *testing.T) {
	status := &types.AppInstanceStatus{
		DisplayName:        "n8-a",
		State:              types.RUNNING,
		Activated:          true,
		CPUPlacementStatus: types.CPUPlacementStatusPlaced,
		RepackFor:          []string{"n6-a"},
		BootTime:           time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
	errInfo := cpuPlacementAdvisory(status)
	if errInfo == nil {
		t.Fatal("a repack member must be reported, or the controller never restarts it")
	}
	if errInfo.Severity != info.Severity_SEVERITY_WARNING {
		t.Errorf("severity %v, want WARNING: the member is running normally", errInfo.Severity)
	}
	if !strings.Contains(errInfo.Description, "n6-a") ||
		!strings.Contains(errInfo.Description, "placed well") {
		t.Errorf("description must say whom it makes room for, and that its own "+
			"placement is fine: %q", errInfo.Description)
	}
	if status.HasError() {
		t.Error("the advisory must not put the member into an error state")
	}
}

// A workload waiting for its planned CPUs is reported, with the workloads it
// waits for and a timestamp that does not move: the wait lasts until they
// leave, so the controller has to be able to tell it from a stuck workload.
func TestCPUPlacementAdvisory_ReportsAWait(t *testing.T) {
	since := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	status := &types.AppInstanceStatus{
		DisplayName: "n6-a",
		CPUWait:     types.CPUWait{Holders: []string{"n8-a"}, Since: since},
	}
	errInfo := cpuPlacementAdvisory(status)
	if errInfo == nil {
		t.Fatal("a waiting workload must be reported")
	}
	if errInfo.Severity != info.Severity_SEVERITY_WARNING {
		t.Errorf("want a WARNING, got %v", errInfo.Severity)
	}
	if !strings.Contains(errInfo.Description, "n8-a") || errInfo.RetryCondition == "" {
		t.Errorf("must name the holders and say what ends the wait: %+v", errInfo)
	}
	if !errInfo.Timestamp.AsTime().Equal(since) {
		t.Errorf("timestamp %v, want when the wait began (%v)", errInfo.Timestamp.AsTime(), since)
	}
	if status.HasError() {
		t.Error("a wait is not an error")
	}
}
