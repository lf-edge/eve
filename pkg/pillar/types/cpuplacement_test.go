// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
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
		{"CPUPolicy fallback", CPUPolicy(200).String(), "unknown(200)"},

		{"CPUNUMAPolicyUnspecified", CPUNUMAPolicyUnspecified.String(), "unspecified"},
		{"CPUNUMAPolicyNone", CPUNUMAPolicyNone.String(), "none"},
		{"CPUNUMAPolicyBestEffort", CPUNUMAPolicyBestEffort.String(), "best-effort"},
		{"CPUNUMAPolicySingleNode", CPUNUMAPolicySingleNode.String(), "single-numa-node"},
		{"CPUNUMAPolicy fallback", CPUNUMAPolicy(200).String(), "unknown(200)"},

		{"CPUIOPlacementUnspecified", CPUIOPlacementUnspecified.String(), "unspecified"},
		{"CPUIOPlacementDedicated", CPUIOPlacementDedicated.String(), "dedicated"},
		{"CPUIOPlacementHousekeeping", CPUIOPlacementHousekeeping.String(), "housekeeping"},
		{"CPUIOPlacement fallback", CPUIOPlacement(200).String(), "unknown(200)"},

		{"CPUPlacementStatusUnspecified", CPUPlacementStatusUnspecified.String(), "unspecified"},
		{"CPUPlacementStatusPlaced", CPUPlacementStatusPlaced.String(), "placed"},
		{"CPUPlacementStatusWaiting", CPUPlacementStatusWaiting.String(), "waiting"},
		{"CPUPlacementStatusRepackAdvised", CPUPlacementStatusRepackAdvised.String(), "repack-advised"},
		{"CPUPlacementStatusNeedsRepack", CPUPlacementStatusNeedsRepack.String(), "needs-repack"},
		{"CPUPlacementStatusInsufficient", CPUPlacementStatusInsufficient.String(), "insufficient"},
		{"CPUPlacementStatusPolicyInvalid", CPUPlacementStatusPolicyInvalid.String(), "policy-invalid"},
		{"CPUPlacementStatusOddVCPU", CPUPlacementStatusOddVCPU.String(), "odd-vcpu"},
		{"CPUPlacementStatusTopologyUnsupported", CPUPlacementStatusTopologyUnsupported.String(), "topology-unsupported"},
		{"CPUPlacementStatusIsolationUnavailable", CPUPlacementStatusIsolationUnavailable.String(), "isolation-unavailable"},
		{"CPUPlacementStatus fallback", CPUPlacementStatus(200).String(), "unknown(200)"},

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

// The reported assignment is what the workload holds: its vCPU CPUs in vCPU
// order, its parked siblings and the shared CPUs its IO threads run on; nothing
// for a workload that holds no CPUs of its own.
func TestDomainStatusCPUAssignment(t *testing.T) {
	var shared DomainStatus
	shared.VmConfig.CPUs = []uint32{0, 1, 2}
	if a := shared.CPUAssignment(); !a.Equal(CPUAssignment{}) {
		t.Errorf("a housekeeping workload holds no CPUs, got %+v", a)
	}

	var pinned DomainStatus
	pinned.VmConfig.CPUs = []uint32{6, 2, 0}
	pinned.OrderedCPUs = []uint32{6, 2}
	pinned.ParkedCPUs = []uint32{14, 10}
	pinned.EmulatorCPUs = []uint32{0}
	want := CPUAssignment{CPUs: []uint32{6, 2}, ParkedCPUs: []uint32{14, 10}, IOCPUs: []uint32{0}}
	if a := pinned.CPUAssignment(); !a.Equal(want) {
		t.Errorf("pinned: got %+v, want %+v", a, want)
	}

	pinned.OrderedCPUs = nil
	if a := pinned.CPUAssignment(); !a.Equal(CPUAssignment{}) {
		t.Errorf("a workload whose CPUs were released holds none, got %+v", a)
	}
}

// DomainStatus embeds VmConfig, so a field of its own named like one of
// VmConfig's would shadow it: Go still compiles, but JSON, which is how pubsub
// carries the status between agents, would drop the embedded one. Both the
// placement policy and domainmgr's verdict on it have to survive the trip.
func TestDomainStatusJSONKeepsPolicyAndVerdict(t *testing.T) {
	var in DomainStatus
	in.VmConfig.CPUPlacement = CPUPlacementPolicy{Policy: CPUPolicyDedicated, Pinned: true,
		FullPCPUsOnly: true, ThreadsPerCore: 1}
	in.CPUPlacementStatus = CPUPlacementStatusRepackAdvised
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
	if out.CPUPlacementStatus != in.CPUPlacementStatus {
		t.Errorf("verdict %v after JSON, want %v", out.CPUPlacementStatus, in.CPUPlacementStatus)
	}
}
