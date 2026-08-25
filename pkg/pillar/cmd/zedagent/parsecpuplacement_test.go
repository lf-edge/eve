// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestParseCPUPlacementPolicy(t *testing.T) {
	tests := []struct {
		name string
		in   *zconfig.VmConfig
		want types.CPUPlacementPolicy
	}{
		{
			name: "nil config",
			in:   nil,
			want: types.CPUPlacementPolicy{},
		},
		{
			name: "no policy sent leaves the zero value",
			in:   &zconfig.VmConfig{},
			want: types.CPUPlacementPolicy{},
		},
		{
			name: "whole-core-smt throughput preset",
			in: &zconfig.VmConfig{
				CpuPolicy:      zconfig.CpuPolicy_CPU_POLICY_DEDICATED,
				FullPcpusOnly:  true,
				ThreadsPerCore: 2,
				NumaPolicy:     zconfig.NumaPolicy_NUMA_POLICY_SINGLE_NUMA_NODE,
				IoPlacement:    zconfig.IoPlacement_IO_PLACEMENT_HOUSEKEEPING,
				IsolationTier:  zconfig.IsolationTier_ISOLATION_TIER_SOFT,
			},
			want: types.CPUPlacementPolicy{
				Policy:         types.CPUPolicyDedicated,
				FullPCPUsOnly:  true,
				ThreadsPerCore: 2,
				NUMAPolicy:     types.CPUNUMAPolicySingleNode,
				IOPlacement:    types.CPUIOPlacementHousekeeping,
				IsolationTier:  types.CPUIsolationTierSoft,
			},
		},
		{
			name: "one-per-core with protection",
			in: &zconfig.VmConfig{
				CpuPolicy:        zconfig.CpuPolicy_CPU_POLICY_DEDICATED,
				FullPcpusOnly:    true,
				ThreadsPerCore:   1,
				NumaPolicy:       zconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT,
				DisruptionPolicy: zconfig.DisruptionPolicy_DISRUPTION_POLICY_PROTECT,
			},
			want: types.CPUPlacementPolicy{
				Policy:           types.CPUPolicyDedicated,
				FullPCPUsOnly:    true,
				ThreadsPerCore:   1,
				NUMAPolicy:       types.CPUNUMAPolicyBestEffort,
				DisruptionPolicy: types.CPUDisruptionPolicyProtect,
			},
		},
		{
			name: "explicitly shared",
			in:   &zconfig.VmConfig{CpuPolicy: zconfig.CpuPolicy_CPU_POLICY_SHARED},
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyShared},
		},
		{
			// A newer controller may send values this EVE does not know; they
			// must degrade to "no preference", never be misread as a real one.
			name: "unknown enum values degrade to unspecified",
			in: &zconfig.VmConfig{
				CpuPolicy:        zconfig.CpuPolicy(99),
				NumaPolicy:       zconfig.NumaPolicy(99),
				IoPlacement:      zconfig.IoPlacement(99),
				IsolationTier:    zconfig.IsolationTier(99),
				DisruptionPolicy: zconfig.DisruptionPolicy(99),
			},
			want: types.CPUPlacementPolicy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCPUPlacementPolicy(tt.in)
			if got != tt.want {
				t.Errorf("parseCPUPlacementPolicy()\n got: %+v\nwant: %+v", got, tt.want)
			}
		})
	}
}

// The legacy pin_cpu flag must keep working unchanged for controllers that do
// not send a policy, and a policy must win when both are present.
func TestCPUsPinnedFromPolicy(t *testing.T) {
	tests := []struct {
		name       string
		policy     types.CPUPlacementPolicy
		pinCPU     bool
		wantPinned bool
	}{
		{"no policy, pin_cpu false", types.CPUPlacementPolicy{}, false, false},
		{"no policy, pin_cpu true (legacy)", types.CPUPlacementPolicy{}, true, true},
		{
			"dedicated policy pins without pin_cpu",
			types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated},
			false,
			true,
		},
		{
			"shared policy overrides a stale pin_cpu",
			types.CPUPlacementPolicy{Policy: types.CPUPolicyShared},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cpusPinnedFromPolicy(tt.policy, tt.pinCPU); got != tt.wantPinned {
				t.Errorf("cpusPinnedFromPolicy() = %v, want %v", got, tt.wantPinned)
			}
		})
	}
}

// The tests below pin every enumerator of every placement enum the controller
// can send. They are written against the proto enum's own name map rather than a
// hand-written list of values, so an enumerator added to eve-api fails here
// instead of silently degrading to "unspecified" -- which for a request the
// device cannot honor (ISOLATION_TIER_HARD is the case that matters) would turn
// a fail-closed refusal into a silent downgrade.

func TestParseCPUPlacementPolicy_CoversEveryCPUPolicy(t *testing.T) {
	want := map[zconfig.CpuPolicy]types.CPUPolicy{
		zconfig.CpuPolicy_CPU_POLICY_UNSPECIFIED: types.CPUPolicyUnspecified,
		zconfig.CpuPolicy_CPU_POLICY_SHARED:      types.CPUPolicyShared,
		zconfig.CpuPolicy_CPU_POLICY_DEDICATED:   types.CPUPolicyDedicated,
	}
	for value, name := range zconfig.CpuPolicy_name {
		policy := zconfig.CpuPolicy(value)
		expected, covered := want[policy]
		if !covered {
			t.Errorf("%s is not covered by this test, so nothing proves "+
				"parseCPUPolicy maps it", name)
			continue
		}
		got := parseCPUPlacementPolicy(&zconfig.VmConfig{CpuPolicy: policy}).Policy
		if got != expected {
			t.Errorf("%s parsed as %v, want %v", name, got, expected)
		}
	}
}

func TestParseCPUPlacementPolicy_CoversEveryNUMAPolicy(t *testing.T) {
	want := map[zconfig.NumaPolicy]types.CPUNUMAPolicy{
		zconfig.NumaPolicy_NUMA_POLICY_UNSPECIFIED:      types.CPUNUMAPolicyUnspecified,
		zconfig.NumaPolicy_NUMA_POLICY_NONE:             types.CPUNUMAPolicyNone,
		zconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT:      types.CPUNUMAPolicyBestEffort,
		zconfig.NumaPolicy_NUMA_POLICY_RESTRICTED:       types.CPUNUMAPolicyRestricted,
		zconfig.NumaPolicy_NUMA_POLICY_SINGLE_NUMA_NODE: types.CPUNUMAPolicySingleNode,
	}
	for value, name := range zconfig.NumaPolicy_name {
		policy := zconfig.NumaPolicy(value)
		expected, covered := want[policy]
		if !covered {
			t.Errorf("%s is not covered by this test, so nothing proves "+
				"parseCPUNUMAPolicy maps it", name)
			continue
		}
		got := parseCPUPlacementPolicy(&zconfig.VmConfig{NumaPolicy: policy}).NUMAPolicy
		if got != expected {
			t.Errorf("%s parsed as %v, want %v", name, got, expected)
		}
	}
}

func TestParseCPUPlacementPolicy_CoversEveryIOPlacement(t *testing.T) {
	want := map[zconfig.IoPlacement]types.CPUIOPlacement{
		zconfig.IoPlacement_IO_PLACEMENT_UNSPECIFIED:  types.CPUIOPlacementUnspecified,
		zconfig.IoPlacement_IO_PLACEMENT_DEDICATED:    types.CPUIOPlacementDedicated,
		zconfig.IoPlacement_IO_PLACEMENT_HOUSEKEEPING: types.CPUIOPlacementHousekeeping,
	}
	for value, name := range zconfig.IoPlacement_name {
		placement := zconfig.IoPlacement(value)
		expected, covered := want[placement]
		if !covered {
			t.Errorf("%s is not covered by this test, so nothing proves "+
				"parseCPUIOPlacement maps it", name)
			continue
		}
		got := parseCPUPlacementPolicy(&zconfig.VmConfig{IoPlacement: placement}).IOPlacement
		if got != expected {
			t.Errorf("%s parsed as %v, want %v", name, got, expected)
		}
	}
}

func TestParseCPUPlacementPolicy_CoversEveryIsolationTier(t *testing.T) {
	want := map[zconfig.IsolationTier]types.CPUIsolationTier{
		zconfig.IsolationTier_ISOLATION_TIER_UNSPECIFIED: types.CPUIsolationTierUnspecified,
		zconfig.IsolationTier_ISOLATION_TIER_NONE:        types.CPUIsolationTierNone,
		zconfig.IsolationTier_ISOLATION_TIER_SOFT:        types.CPUIsolationTierSoft,
		zconfig.IsolationTier_ISOLATION_TIER_HARD:        types.CPUIsolationTierHard,
	}
	for value, name := range zconfig.IsolationTier_name {
		tier := zconfig.IsolationTier(value)
		expected, covered := want[tier]
		if !covered {
			t.Errorf("%s is not covered by this test, so nothing proves "+
				"parseCPUIsolationTier maps it", name)
			continue
		}
		got := parseCPUPlacementPolicy(&zconfig.VmConfig{IsolationTier: tier}).IsolationTier
		if got != expected {
			t.Errorf("%s parsed as %v, want %v", name, got, expected)
		}
	}
	// Hard isolation needs a node booted with kernel isolation, so it has to
	// arrive as itself: parsed as anything else the request is silently
	// downgraded to soft isolation instead of being placed on isolated cores.
	if !types.CPUIsolationTierHard.NeedsKernelIsolation() {
		t.Error("hard isolation must demand kernel isolation")
	}
}

func TestParseCPUPlacementPolicy_CoversEveryDisruptionPolicy(t *testing.T) {
	want := map[zconfig.DisruptionPolicy]types.CPUDisruptionPolicy{
		zconfig.DisruptionPolicy_DISRUPTION_POLICY_UNSPECIFIED: types.CPUDisruptionPolicyUnspecified,
		zconfig.DisruptionPolicy_DISRUPTION_POLICY_ALLOW:       types.CPUDisruptionPolicyAllow,
		zconfig.DisruptionPolicy_DISRUPTION_POLICY_PROTECT:     types.CPUDisruptionPolicyProtect,
	}
	for value, name := range zconfig.DisruptionPolicy_name {
		policy := zconfig.DisruptionPolicy(value)
		expected, covered := want[policy]
		if !covered {
			t.Errorf("%s is not covered by this test, so nothing proves "+
				"parseCPUDisruptionPolicy maps it", name)
			continue
		}
		got := parseCPUPlacementPolicy(
			&zconfig.VmConfig{DisruptionPolicy: policy}).DisruptionPolicy
		if got != expected {
			t.Errorf("%s parsed as %v, want %v", name, got, expected)
		}
	}
}
