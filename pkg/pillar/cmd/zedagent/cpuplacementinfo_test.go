// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func repackableApp() *types.AppInstanceStatus {
	status := &types.AppInstanceStatus{
		DisplayName: "vpp",
		State:       types.RUNNING,
		Activated:   true,
		Placement:   types.CPUPlacementState{Verdict: types.CPUPlacementPlacedSuboptimal},
		BootTime:    time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	return status
}

// verdicts is every CPU placement verdict this EVE knows, so a verdict added
// later is covered without touching the tests.
func verdicts() []types.CPUPlacementVerdict {
	var out []types.CPUPlacementVerdict
	for v := types.CPUPlacementVerdict(0); !strings.HasPrefix(v.String(), "unknown("); v++ {
		out = append(out, v)
	}
	return out
}

// Each verdict goes on the wire as the status of the same name, or as
// CPU_PLACEMENT_STATUS_FAILED with the error of that name. Placed worse than
// planned has no status of its own: it is REPACK_ADVISED.
func TestCPUPlacementOnTheWire_EveryVerdict(t *testing.T) {
	renamed := map[types.CPUPlacementVerdict]string{
		types.CPUPlacementPlacedSuboptimal: "CPU_PLACEMENT_STATUS_REPACK_ADVISED",
	}
	all := verdicts()
	if last := all[len(all)-1]; last < types.CPUPlacementIsolationUnavailable {
		t.Fatalf("the loop stopped early, at %v", last)
	}
	for _, v := range all {
		status, reason := cpuPlacementOnTheWire(types.CPUPlacementState{Verdict: v})
		name := strings.ToUpper(strings.ReplaceAll(v.String(), "-", "_"))
		got := status.String()
		if status == info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_FAILED {
			got = reason.String()
			name = "CPU_PLACEMENT_ERROR_" + name
		} else {
			if reason != info.CPUPlacementError_CPU_PLACEMENT_ERROR_UNSPECIFIED {
				t.Errorf("%v carries %v without FAILED", v, reason)
			}
			name = "CPU_PLACEMENT_STATUS_" + name
		}
		if want, ok := renamed[v]; ok {
			name = want
		}
		if got != name {
			t.Errorf("%v goes on the wire as %s, want %s", v, got, name)
		}
	}
}

// What the controller acts on is domainmgr's verdict, with what only the plan
// knows laid over it: a wait for the workloads holding its planned CPUs, and a
// part in another workload's repack.
func TestCPUPlacementOnTheWire_WaitAndRepack(t *testing.T) {
	const (
		unspecified   = info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_UNSPECIFIED
		placed        = info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_PLACED
		waiting       = info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_WAITING
		repackAdvised = info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_REPACK_ADVISED
	)
	wait := types.CPUWait{Holders: []string{"n8-a"}, Since: time.Now()}
	for _, tt := range []struct {
		name  string
		state types.CPUPlacementState
		want  info.CPUPlacementStatus
	}{
		{"no CPU request", types.CPUPlacementState{}, unspecified},
		{"placed", types.CPUPlacementState{Verdict: types.CPUPlacementPlaced}, placed},
		{"placed worse than planned", types.CPUPlacementState{
			Verdict: types.CPUPlacementPlacedSuboptimal}, repackAdvised},
		{"placed worse than planned, in another workload's way", types.CPUPlacementState{
			Verdict: types.CPUPlacementPlacedSuboptimal, RepackFor: []string{"n6-a"}},
			repackAdvised},
		{"placed well, in another workload's way", types.CPUPlacementState{
			Verdict: types.CPUPlacementPlaced, RepackFor: []string{"n6-a"}}, repackAdvised},
		{"waiting for its planned CPUs", types.CPUPlacementState{Wait: wait}, waiting},
		{"waiting for the application set",
			types.CPUPlacementState{Wait: types.CPUWait{AppSet: true}}, unspecified},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, reason := cpuPlacementOnTheWire(tt.state)
			if status != tt.want || reason != info.CPUPlacementError_CPU_PLACEMENT_ERROR_UNSPECIFIED {
				t.Errorf("got %v/%v, want %v with no error", status, reason, tt.want)
			}
		})
	}
}

// The pool kinds and issues go on the wire as numbers, so each must be the
// wire value of the same name.
func TestCPUPoolEnumsMatchTheWire(t *testing.T) {
	kinds := 0
	for k := types.CPUPoolKind(0); !strings.HasPrefix(k.String(), "unknown("); k++ {
		name := "CPU_POOL_KIND_" + strings.ToUpper(k.String())
		if got := info.CPUPoolKind(k).String(); got != name {
			t.Errorf("pool kind %v goes on the wire as %s, want %s", k, got, name)
		}
		kinds++
	}
	if kinds != len(info.CPUPoolKind_name) {
		t.Errorf("the device has %d pool kinds, the wire %d", kinds, len(info.CPUPoolKind_name))
	}
	// CPUPoolIssue has no names of its own; the table must cover the wire.
	issues := map[types.CPUPoolIssue]info.CPUPoolIssue{
		types.CPUPoolIssueUnspecified:  info.CPUPoolIssue_CPU_POOL_ISSUE_UNSPECIFIED,
		types.CPUPoolIssueReservedCPUs: info.CPUPoolIssue_CPU_POOL_ISSUE_RESERVED_CPUS,
		types.CPUPoolIssuePartialCore:  info.CPUPoolIssue_CPU_POOL_ISSUE_PARTIAL_CORE,
	}
	if len(issues) != len(info.CPUPoolIssue_name) {
		t.Errorf("the table covers %d pool issues, the wire has %d", len(issues),
			len(info.CPUPoolIssue_name))
	}
	for device, wire := range issues {
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
	for _, verdict := range verdicts() {
		if verdict == types.CPUPlacementPlacedSuboptimal {
			continue
		}
		status := repackableApp()
		status.Placement.Verdict = verdict
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
// PublishAppInfoToZedCloud needs the full zedagentContext (app IPs, network
// instances, the send queue) to call; this covers what it builds app_err from:
// the app's errors, then reportAppCPUPlacement's advisory.
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
	if got, _ := cpuPlacementOnTheWire(status.Placement); got != info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_REPACK_ADVISED {
		t.Errorf("status %v, want REPACK_ADVISED: the app's error must not hide "+
			"that it is part of a repack", got)
	}
	// And the app's info carries both, the app's own error first.
	app := &info.ZInfoApp{AppErr: appErrors(status)}
	reportAppCPUPlacement(app, status)
	if len(app.AppErr) != 2 || app.AppErr[0].Severity != info.Severity_SEVERITY_ERROR ||
		app.AppErr[1].Severity != info.Severity_SEVERITY_WARNING {
		t.Errorf("want the app's ERROR then the advisory WARNING, got %v", app.AppErr)
	}
}

// A repack member is placed well itself but stands in another workload's way.
// It must still be reported as REPACK_ADVISED, so the controller's repack
// restarts it with the workload it makes room for, but not with the wording
// that says its own placement is bad.
func TestCPUPlacementAdvisory_ReportsRepackMember(t *testing.T) {
	status := &types.AppInstanceStatus{
		DisplayName: "n8-a",
		State:       types.RUNNING,
		Activated:   true,
		Placement: types.CPUPlacementState{
			Verdict:   types.CPUPlacementPlaced,
			RepackFor: []string{"n6-a"},
		},
		BootTime: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
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
		Placement: types.CPUPlacementState{
			Wait: types.CPUWait{Holders: []string{"n8-a"}, Since: since},
		},
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

// The CPU part of an app's info: where it stands, why a refusal was refused,
// the advisory for a placement that is fine but improvable, and the CPUs it
// holds, each in its own field. A vCPU CPU reported as parked, or the reverse,
// would tell the controller the workload runs where it does not.
func TestReportAppCPUPlacement(t *testing.T) {
	const (
		noReason = info.CPUPlacementError_CPU_PLACEMENT_ERROR_UNSPECIFIED
		warning  = info.Severity_SEVERITY_WARNING
	)
	holding := types.CPUAssignment{
		CPUs:       []uint32{2, 3},
		ParkedCPUs: []uint32{6, 7},
		IOCPUs:     []uint32{0},
		Guest:      types.CPUTopology{Sockets: 1, Cores: 2, Threads: 1},
	}
	for _, tt := range []struct {
		name       string
		state      types.CPUPlacementState
		wantStatus info.CPUPlacementStatus
		wantReason info.CPUPlacementError
		// wantAdvisory is a phrase of the advisory's description; "" is none.
		wantAdvisory string
		wantCPUs     *types.CPUAssignment
	}{
		{name: "no CPU request",
			wantStatus: info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_UNSPECIFIED,
			wantReason: noReason},
		{name: "placed",
			state:      types.CPUPlacementState{Verdict: types.CPUPlacementPlaced, Assigned: holding},
			wantStatus: info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_PLACED,
			wantReason: noReason, wantCPUs: &holding},
		{name: "placed worse than planned",
			state: types.CPUPlacementState{Verdict: types.CPUPlacementPlacedSuboptimal,
				Assigned: holding},
			wantStatus:   info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_REPACK_ADVISED,
			wantReason:   noReason,
			wantAdvisory: "worse than", wantCPUs: &holding},
		{name: "placed well, in another workload's way",
			state: types.CPUPlacementState{Verdict: types.CPUPlacementPlaced,
				Assigned: holding, RepackFor: []string{"n6-a"}},
			wantStatus:   info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_REPACK_ADVISED,
			wantReason:   noReason,
			wantAdvisory: "placed well", wantCPUs: &holding},
		{name: "waiting for its planned CPUs",
			state: types.CPUPlacementState{Wait: types.CPUWait{
				Holders: []string{"n8-a"}, Since: time.Now()}},
			wantStatus:   info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_WAITING,
			wantReason:   noReason,
			wantAdvisory: "waiting for n8-a"},
		{name: "refused",
			state:      types.CPUPlacementState{Verdict: types.CPUPlacementInsufficient},
			wantStatus: info.CPUPlacementStatus_CPU_PLACEMENT_STATUS_FAILED,
			wantReason: info.CPUPlacementError_CPU_PLACEMENT_ERROR_INSUFFICIENT},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status := &types.AppInstanceStatus{DisplayName: "app", Placement: tt.state,
				BootTime: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)}
			app := &info.ZInfoApp{}
			reportAppCPUPlacement(app, status)

			if app.CpuPlacementStatus != tt.wantStatus || app.CpuPlacementError != tt.wantReason {
				t.Errorf("cpu_placement_status/error %v/%v, want %v/%v",
					app.CpuPlacementStatus, app.CpuPlacementError, tt.wantStatus, tt.wantReason)
			}
			switch {
			case tt.wantAdvisory == "" && len(app.AppErr) != 0:
				t.Errorf("want no advisory, got %v", app.AppErr)
			case tt.wantAdvisory != "" && (len(app.AppErr) != 1 ||
				app.AppErr[0].Severity != warning ||
				!strings.Contains(app.AppErr[0].Description, tt.wantAdvisory)):
				t.Errorf("want one WARNING saying %q, got %v", tt.wantAdvisory, app.AppErr)
			}
			if tt.wantCPUs == nil {
				if app.AssignedCpus != nil {
					t.Errorf("holds no CPUs, but assigned_cpus is %v", app.AssignedCpus)
				}
				return
			}
			got := app.AssignedCpus
			if got == nil || !slices.Equal(got.CpuIds, tt.wantCPUs.CPUs) ||
				!slices.Equal(got.ParkedCpuIds, tt.wantCPUs.ParkedCPUs) ||
				!slices.Equal(got.IoCpuIds, tt.wantCPUs.IOCPUs) {
				t.Errorf("assigned_cpus %v, want cpu_ids %v, parked_cpu_ids %v, io_cpu_ids %v",
					got, tt.wantCPUs.CPUs, tt.wantCPUs.ParkedCPUs, tt.wantCPUs.IOCPUs)
			}
		})
	}
}
