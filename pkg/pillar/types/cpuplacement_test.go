// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestCPUPlacementIsTopologyAware(t *testing.T) {
	tests := []struct {
		name string
		p    CPUPlacementPolicy
		want bool
	}{
		{"zero value is shared", CPUPlacementPolicy{}, false},
		{"housekeeping is not topology-aware", CPUPlacementPolicy{Policy: CPUPolicyHousekeeping}, false},
		{
			"dedicated without full-pcpus-only stays thread-granular",
			CPUPlacementPolicy{Policy: CPUPolicyDedicated},
			false,
		},
		{
			"dedicated with full-pcpus-only",
			CPUPlacementPolicy{Policy: CPUPolicyDedicated, FullPCPUsOnly: true},
			true,
		},
		{
			"isolated with full-pcpus-only",
			CPUPlacementPolicy{Policy: CPUPolicyIsolated, FullPCPUsOnly: true},
			true,
		},
		{
			"full-pcpus-only alone means nothing without CPUs of its own",
			CPUPlacementPolicy{FullPCPUsOnly: true},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IsTopologyAware(); got != tt.want {
				t.Errorf("IsTopologyAware() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The pool decides whether a workload has CPUs of its own and whether they must
// be kernel-isolated; pinning is a separate field and changes neither.
func TestCPUPlacementPool(t *testing.T) {
	tests := []struct {
		policy             CPUPolicy
		ownCPUs, isolation bool
	}{
		{CPUPolicyUnspecified, false, false},
		{CPUPolicyHousekeeping, false, false},
		{CPUPolicyDedicated, true, false},
		{CPUPolicyIsolated, true, true},
	}
	for _, tt := range tests {
		for _, pinned := range []bool{false, true} {
			p := CPUPlacementPolicy{Policy: tt.policy, Pinned: pinned}
			if got := p.HasOwnCPUs(); got != tt.ownCPUs {
				t.Errorf("%v pinned=%v: HasOwnCPUs() = %v, want %v",
					tt.policy, pinned, got, tt.ownCPUs)
			}
			if got := p.NeedsKernelIsolation(); got != tt.isolation {
				t.Errorf("%v pinned=%v: NeedsKernelIsolation() = %v, want %v",
					tt.policy, pinned, got, tt.isolation)
			}
		}
	}
}

// The legacy rule applies only to a policy the controller left unset: pin_cpu
// then means CPUs of the workload's own, pinned for a VM and not for a container.
func TestCPUPlacementResolveLegacy(t *testing.T) {
	tests := []struct {
		name              string
		in                CPUPlacementPolicy
		pinCPU, container bool
		want              CPUPlacementPolicy
	}{
		{"no pin_cpu is shared", CPUPlacementPolicy{}, false, false,
			CPUPlacementPolicy{Policy: CPUPolicyHousekeeping}},
		{"pin_cpu on a VM is dedicated and pinned", CPUPlacementPolicy{}, true, false,
			CPUPlacementPolicy{Policy: CPUPolicyDedicated, Pinned: true}},
		{"pin_cpu on a container is dedicated and not pinned", CPUPlacementPolicy{}, true, true,
			CPUPlacementPolicy{Policy: CPUPolicyDedicated}},
		{"an explicit policy is kept", CPUPlacementPolicy{Policy: CPUPolicyHousekeeping, Pinned: true}, true, false,
			CPUPlacementPolicy{Policy: CPUPolicyHousekeeping, Pinned: true}},
		{"refining fields without a policy are not legacy",
			CPUPlacementPolicy{FullPCPUsOnly: true}, true, false,
			CPUPlacementPolicy{Policy: CPUPolicyHousekeeping, Pinned: true, FullPCPUsOnly: true}},
		{"an explicit unpinned isolated policy is kept", CPUPlacementPolicy{Policy: CPUPolicyIsolated}, true, false,
			CPUPlacementPolicy{Policy: CPUPolicyIsolated}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.ResolveLegacy(tt.pinCPU, tt.container); got != tt.want {
				t.Errorf("ResolveLegacy() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A dedicated workload that asks for whole cores and does not say how many
// threads per core gets both siblings, matching the API's documented default.
func TestCPUPlacementEffectiveThreadsPerCore(t *testing.T) {
	tests := []struct {
		name string
		p    CPUPlacementPolicy
		want uint32
	}{
		{"unset defaults to 2", CPUPlacementPolicy{Policy: CPUPolicyDedicated, FullPCPUsOnly: true}, 2},
		{"explicit 1 is honored", CPUPlacementPolicy{Policy: CPUPolicyDedicated, FullPCPUsOnly: true, ThreadsPerCore: 1}, 1},
		{"explicit 2 is honored", CPUPlacementPolicy{Policy: CPUPolicyDedicated, FullPCPUsOnly: true, ThreadsPerCore: 2}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.EffectiveThreadsPerCore(); got != tt.want {
				t.Errorf("EffectiveThreadsPerCore() = %d, want %d", got, tt.want)
			}
		})
	}
}

// Strings appear in logs and status; they must be stable and not panic on values
// outside the known range. Every enumerator is listed, so an added value without
// a String() case is caught here rather than seen as "unknown(N)" in the field.
func TestCPUPlacementStrings(t *testing.T) {
	cases := []struct {
		name, got, want string
	}{
		{"CPUPolicyUnspecified", CPUPolicyUnspecified.String(), "unspecified"},
		{"CPUPolicyHousekeeping", CPUPolicyHousekeeping.String(), "housekeeping"},
		{"CPUPolicyDedicated", CPUPolicyDedicated.String(), "dedicated"},
		{"CPUPolicyIsolated", CPUPolicyIsolated.String(), "isolated"},
		{"CPUPolicyUnknown", CPUPolicyUnknown.String(), "unknown"},
		{"CPUPolicy fallback", CPUPolicy(200).String(), "unknown(200)"},

		{"CPUNUMAPolicyUnspecified", CPUNUMAPolicyUnspecified.String(), "unspecified"},
		{"CPUNUMAPolicyNone", CPUNUMAPolicyNone.String(), "none"},
		{"CPUNUMAPolicyBestEffort", CPUNUMAPolicyBestEffort.String(), "best-effort"},
		{"CPUNUMAPolicySingleNode", CPUNUMAPolicySingleNode.String(), "single-numa-node"},
		{"CPUNUMAPolicyUnknown", CPUNUMAPolicyUnknown.String(), "unknown"},
		{"CPUNUMAPolicy fallback", CPUNUMAPolicy(200).String(), "unknown(200)"},

		{"CPUIOPlacementUnspecified", CPUIOPlacementUnspecified.String(), "unspecified"},
		{"CPUIOPlacementDedicated", CPUIOPlacementDedicated.String(), "dedicated"},
		{"CPUIOPlacementHousekeeping", CPUIOPlacementHousekeeping.String(), "housekeeping"},
		{"CPUIOPlacementUnknown", CPUIOPlacementUnknown.String(), "unknown"},
		{"CPUIOPlacement fallback", CPUIOPlacement(200).String(), "unknown(200)"},

		{"CPUPlacementUnspecified", CPUPlacementUnspecified.String(), "unspecified"},
		{"CPUPlacementPlaced", CPUPlacementPlaced.String(), "placed"},
		{"CPUPlacementPlacedSuboptimal", CPUPlacementPlacedSuboptimal.String(), "placed-suboptimal"},
		{"CPUPlacementNeedsRepack", CPUPlacementNeedsRepack.String(), "needs-repack"},
		{"CPUPlacementInsufficient", CPUPlacementInsufficient.String(), "insufficient"},
		{"CPUPlacementPolicyInvalid", CPUPlacementPolicyInvalid.String(), "policy-invalid"},
		{"CPUPlacementOddVCPU", CPUPlacementOddVCPU.String(), "odd-vcpu"},
		{"CPUPlacementTopologyUnsupported", CPUPlacementTopologyUnsupported.String(), "topology-unsupported"},
		{"CPUPlacementIsolationUnavailable", CPUPlacementIsolationUnavailable.String(), "isolation-unavailable"},
		{"CPUPlacementVerdict fallback", CPUPlacementVerdict(200).String(), "unknown(200)"},

		{"CPUPoolKindUnspecified", CPUPoolKindUnspecified.String(), "unspecified"},
		{"CPUPoolKindHousekeeping", CPUPoolKindHousekeeping.String(), "housekeeping"},
		{"CPUPoolKindDedicated", CPUPoolKindDedicated.String(), "dedicated"},
		{"CPUPoolKindIsolated", CPUPoolKindIsolated.String(), "isolated"},
		{"CPUPoolKind fallback", CPUPoolKind(200).String(), "unknown(200)"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: String() = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// A workload's CPUs, as the assignment names them: its domain's cpuset is its
// vCPUs' CPUs and its IO CPUs, never the parked siblings; its non-vCPU threads
// run on the IO CPUs when it has them, else on its vCPUs' CPUs.
func TestCPUAssignment(t *testing.T) {
	a := CPUAssignment{CPUs: []uint32{6, 2}, ParkedCPUs: []uint32{14, 10},
		IOCPUs: []uint32{0}, Guest: CPUTopology{Sockets: 1, Cores: 2, Threads: 1}}
	if !a.Holds() || (CPUAssignment{}).Holds() {
		t.Error("Holds: an assignment holds CPUs exactly when it names vCPU CPUs")
	}
	if got := a.DomainCPUs(); !slices.Equal(got, []uint32{6, 2, 0}) {
		t.Errorf("DomainCPUs = %v, want [6 2 0]", got)
	}
	if got := a.EmulatorCPUs(); !slices.Equal(got, []uint32{0}) {
		t.Errorf("EmulatorCPUs with IO CPUs = %v, want [0]", got)
	}
	ioOwn := a
	ioOwn.IOCPUs = nil
	if got := ioOwn.EmulatorCPUs(); !slices.Equal(got, []uint32{6, 2}) {
		t.Errorf("EmulatorCPUs without IO CPUs = %v, want [6 2]", got)
	}
	other := a
	other.Guest.Threads = 2
	if !a.Equal(a) || a.Equal(other) || a.Equal(ioOwn) {
		t.Error("Equal must compare every CPU list and the guest topology")
	}
}

// A domain holding CPUs of its own starts where its non-vCPU threads run: its
// IO CPUs, or under io_placement=dedicated its vCPUs' CPUs. Any other domain
// starts on its cpuset.
func TestDomainStatusStartCPUs(t *testing.T) {
	var shared DomainStatus
	shared.VmConfig.CPUs = []uint32{0, 1, 2}
	if got := shared.StartCPUs(); !slices.Equal(got, []uint32{0, 1, 2}) {
		t.Errorf("shared: StartCPUs = %v, want its cpuset", got)
	}
	var pinned DomainStatus
	pinned.VmConfig.CPUs = []uint32{6, 2, 0}
	pinned.Placement.Assigned = CPUAssignment{CPUs: []uint32{6, 2}, IOCPUs: []uint32{0}}
	if got := pinned.StartCPUs(); !slices.Equal(got, []uint32{0}) {
		t.Errorf("pinned with IO CPUs: StartCPUs = %v, want [0]", got)
	}
	pinned.VmConfig.CPUs = []uint32{6, 2}
	pinned.Placement.Assigned.IOCPUs = nil
	if got := pinned.StartCPUs(); !slices.Equal(got, []uint32{6, 2}) {
		t.Errorf("pinned, IO on its own CPUs: StartCPUs = %v, want [6 2]", got)
	}
}

func TestCPUPlacementStateEqual(t *testing.T) {
	s := CPUPlacementState{Verdict: CPUPlacementPlaced,
		Assigned: CPUAssignment{CPUs: []uint32{2}}, RepackFor: []string{"a"},
		Wait: CPUWait{Holders: []string{"b"}}}
	if !s.Equal(s) || !(CPUPlacementState{}).Equal(CPUPlacementState{}) {
		t.Error("a state equals itself")
	}
	for name, change := range map[string]func(*CPUPlacementState){
		"verdict":    func(o *CPUPlacementState) { o.Verdict = CPUPlacementPlacedSuboptimal },
		"assigned":   func(o *CPUPlacementState) { o.Assigned.CPUs = []uint32{3} },
		"repack for": func(o *CPUPlacementState) { o.RepackFor = nil },
		"wait":       func(o *CPUPlacementState) { o.Wait = CPUWait{} },
	} {
		o := s
		change(&o)
		if s.Equal(o) {
			t.Errorf("a different %s compares equal", name)
		}
	}
}

func TestCPUPlacementPolicyUnknownField(t *testing.T) {
	for want, p := range map[string]CPUPlacementPolicy{
		"":             {Policy: CPUPolicyDedicated, NUMAPolicy: CPUNUMAPolicySingleNode},
		"cpu_policy":   {Policy: CPUPolicyUnknown},
		"numa_policy":  {Policy: CPUPolicyDedicated, NUMAPolicy: CPUNUMAPolicyUnknown},
		"io_placement": {Policy: CPUPolicyDedicated, IOPlacement: CPUIOPlacementUnknown},
	} {
		if got := p.UnknownField(); got != want {
			t.Errorf("%+v: UnknownField = %q, want %q", p, got, want)
		}
	}
}

// DomainStatus embeds VmConfig, so a field of its own named like one of
// VmConfig's would shadow it: Go still compiles, but JSON, which is how pubsub
// carries the status between agents, would drop the embedded one. Both the
// placement policy and domainmgr's state on it have to survive the trip.
func TestDomainStatusJSONKeepsPolicyAndPlacement(t *testing.T) {
	var in DomainStatus
	in.VmConfig.CPUPlacement = CPUPlacementPolicy{Policy: CPUPolicyDedicated, Pinned: true,
		FullPCPUsOnly: true, ThreadsPerCore: 1}
	in.Placement = CPUPlacementState{Verdict: CPUPlacementPlacedSuboptimal,
		Assigned: CPUAssignment{CPUs: []uint32{4}, ParkedCPUs: []uint32{12},
			Guest: CPUTopology{Sockets: 1, Cores: 1, Threads: 1}}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out DomainStatus
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.VmConfig.CPUPlacement != in.VmConfig.CPUPlacement {
		t.Errorf("policy %+v after JSON, want %+v", out.VmConfig.CPUPlacement, in.VmConfig.CPUPlacement)
	}
	if !out.Placement.Equal(in.Placement) {
		t.Errorf("placement %+v after JSON, want %+v", out.Placement, in.Placement)
	}
}
