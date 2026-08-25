// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

func TestCPUPlacementIsTopologyAware(t *testing.T) {
	tests := []struct {
		name string
		p    CPUPlacementPolicy
		want bool
	}{
		{"zero value is legacy", CPUPlacementPolicy{}, false},
		{"shared is not topology-aware", CPUPlacementPolicy{Policy: CPUPolicyShared}, false},
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
			"full-pcpus-only alone means nothing without a dedicated policy",
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

func TestCPUPlacementIsDedicated(t *testing.T) {
	if (CPUPlacementPolicy{}).IsDedicated() {
		t.Error("zero value must not be dedicated")
	}
	if (CPUPlacementPolicy{Policy: CPUPolicyShared}).IsDedicated() {
		t.Error("shared must not be dedicated")
	}
	if !(CPUPlacementPolicy{Policy: CPUPolicyDedicated}).IsDedicated() {
		t.Error("dedicated policy must report dedicated")
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

// The isolation tier a workload may request is gated by what the device can
// actually do; only "none" and "soft" are implementable without a kernel
// command-line change.
func TestCPUIsolationTierSupported(t *testing.T) {
	runtimeSatisfiable := []CPUIsolationTier{
		CPUIsolationTierUnspecified,
		CPUIsolationTierNone,
		CPUIsolationTierSoft,
	}
	for _, tier := range runtimeSatisfiable {
		if tier.NeedsKernelIsolation() {
			t.Errorf("tier %v is satisfiable at runtime and must not demand "+
				"kernel isolation", tier)
		}
	}
	if !CPUIsolationTierHard.NeedsKernelIsolation() {
		t.Error("hard isolation cannot be arranged at runtime: it must demand a " +
			"node booted with isolcpus")
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
		{"CPUPolicyShared", CPUPolicyShared.String(), "shared"},
		{"CPUPolicyDedicated", CPUPolicyDedicated.String(), "dedicated"},
		{"CPUPolicy fallback", CPUPolicy(200).String(), "unknown(200)"},

		{"CPUNUMAPolicyUnspecified", CPUNUMAPolicyUnspecified.String(), "unspecified"},
		{"CPUNUMAPolicyNone", CPUNUMAPolicyNone.String(), "none"},
		{"CPUNUMAPolicyBestEffort", CPUNUMAPolicyBestEffort.String(), "best-effort"},
		{"CPUNUMAPolicyRestricted", CPUNUMAPolicyRestricted.String(), "restricted"},
		{"CPUNUMAPolicySingleNode", CPUNUMAPolicySingleNode.String(), "single-numa-node"},
		{"CPUNUMAPolicy fallback", CPUNUMAPolicy(200).String(), "unknown(200)"},

		{"CPUIOPlacementUnspecified", CPUIOPlacementUnspecified.String(), "unspecified"},
		{"CPUIOPlacementDedicated", CPUIOPlacementDedicated.String(), "dedicated"},
		{"CPUIOPlacementHousekeeping", CPUIOPlacementHousekeeping.String(), "housekeeping"},
		{"CPUIOPlacement fallback", CPUIOPlacement(200).String(), "unknown(200)"},

		{"CPUIsolationTierUnspecified", CPUIsolationTierUnspecified.String(), "unspecified"},
		{"CPUIsolationTierNone", CPUIsolationTierNone.String(), "none"},
		{"CPUIsolationTierSoft", CPUIsolationTierSoft.String(), "soft"},
		{"CPUIsolationTierHard", CPUIsolationTierHard.String(), "hard"},
		{"CPUIsolationTier fallback", CPUIsolationTier(200).String(), "unknown(200)"},

		{"CPUDisruptionPolicyUnspecified", CPUDisruptionPolicyUnspecified.String(), "unspecified"},
		{"CPUDisruptionPolicyAllow", CPUDisruptionPolicyAllow.String(), "allow"},
		{"CPUDisruptionPolicyProtect", CPUDisruptionPolicyProtect.String(), "protect"},
		{"CPUDisruptionPolicy fallback", CPUDisruptionPolicy(200).String(), "unknown(200)"},

		{"CPUPlacementQualityUnspecified", CPUPlacementQualityUnspecified.String(), "unspecified"},
		{"CPUPlacementQualityOptimal", CPUPlacementQualityOptimal.String(), "optimal"},
		{"CPUPlacementQualityNeedsRepack", CPUPlacementQualityNeedsRepack.String(), "needs-repack"},
		{"CPUPlacementQuality fallback", CPUPlacementQuality(200).String(), "unknown(200)"},

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
