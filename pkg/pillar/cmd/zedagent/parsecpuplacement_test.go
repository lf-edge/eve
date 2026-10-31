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
			name: "nil config is shared",
			in:   nil,
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyHousekeeping},
		},
		{
			name: "no policy and no pin_cpu is shared",
			in:   &zconfig.VmConfig{},
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyHousekeeping},
		},
		{
			name: "whole cores, both threads, pinned",
			in: &zconfig.VmConfig{
				CpuPolicy:      zconfig.CpuPolicy_CPU_POLICY_DEDICATED,
				PinCpu:         true,
				FullPcpusOnly:  true,
				ThreadsPerCore: 2,
				NumaPolicy:     zconfig.NumaPolicy_NUMA_POLICY_SINGLE_NUMA_NODE,
				IoPlacement:    zconfig.IoPlacement_IO_PLACEMENT_HOUSEKEEPING,
			},
			want: types.CPUPlacementPolicy{
				Policy:         types.CPUPolicyDedicated,
				Pinned:         true,
				FullPCPUsOnly:  true,
				ThreadsPerCore: 2,
				NUMAPolicy:     types.CPUNUMAPolicySingleNode,
				IOPlacement:    types.CPUIOPlacementHousekeeping,
			},
		},
		{
			name: "isolated, one thread per core, pinned",
			in: &zconfig.VmConfig{
				CpuPolicy:      zconfig.CpuPolicy_CPU_POLICY_ISOLATED,
				PinCpu:         true,
				FullPcpusOnly:  true,
				ThreadsPerCore: 1,
			},
			want: types.CPUPlacementPolicy{
				Policy:         types.CPUPolicyIsolated,
				Pinned:         true,
				FullPCPUsOnly:  true,
				ThreadsPerCore: 1,
			},
		},
		{
			// The RT container: CPUs of its own, the kernel isolating them, and
			// the workload placing its own threads.
			name: "isolated and not pinned is kept as sent",
			in: &zconfig.VmConfig{
				CpuPolicy:          zconfig.CpuPolicy_CPU_POLICY_ISOLATED,
				FullPcpusOnly:      true,
				VirtualizationMode: zconfig.VmMode_NOHYPER,
			},
			want: types.CPUPlacementPolicy{
				Policy:        types.CPUPolicyIsolated,
				FullPCPUsOnly: true,
			},
		},
		{
			// Every field keeps its meaning: pin_cpu does not turn a shared
			// policy into a dedicated one. domainmgr refuses the combination.
			name: "shared with pin_cpu is kept as sent",
			in: &zconfig.VmConfig{
				CpuPolicy: zconfig.CpuPolicy_CPU_POLICY_HOUSEKEEPING,
				PinCpu:    true,
			},
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyHousekeeping, Pinned: true},
		},
		{
			name: "legacy pin_cpu on a VM is dedicated and pinned",
			in:   &zconfig.VmConfig{PinCpu: true},
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated, Pinned: true},
		},
		{
			name: "legacy pin_cpu on a container is dedicated and not pinned",
			in:   &zconfig.VmConfig{PinCpu: true, VirtualizationMode: zconfig.VmMode_NOHYPER},
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated},
		},
		{
			// A newer controller may send values this EVE does not know; they
			// must degrade to "no preference", never be misread as a real one.
			name: "unknown enum values degrade to unspecified",
			in: &zconfig.VmConfig{
				CpuPolicy:   zconfig.CpuPolicy(99),
				NumaPolicy:  zconfig.NumaPolicy(99),
				IoPlacement: zconfig.IoPlacement(99),
			},
			want: types.CPUPlacementPolicy{Policy: types.CPUPolicyHousekeeping},
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

// The tests below pin every enumerator of every placement enum the controller
// can send. They are written against the proto enum's own name map rather than a
// hand-written list of values, so an enumerator added to eve-api fails here
// instead of silently degrading to "unspecified" -- which for CPU_POLICY_ISOLATED
// would turn a request for kernel-isolated CPUs into a shared workload.

func TestParseCPUPolicy_CoversEveryCPUPolicy(t *testing.T) {
	want := map[zconfig.CpuPolicy]types.CPUPolicy{
		zconfig.CpuPolicy_CPU_POLICY_UNSPECIFIED:  types.CPUPolicyUnspecified,
		zconfig.CpuPolicy_CPU_POLICY_HOUSEKEEPING: types.CPUPolicyHousekeeping,
		zconfig.CpuPolicy_CPU_POLICY_DEDICATED:    types.CPUPolicyDedicated,
		zconfig.CpuPolicy_CPU_POLICY_ISOLATED:     types.CPUPolicyIsolated,
	}
	for value, name := range zconfig.CpuPolicy_name {
		policy := zconfig.CpuPolicy(value)
		expected, covered := want[policy]
		if !covered {
			t.Errorf("%s is not covered by this test, so nothing proves "+
				"parseCPUPolicy maps it", name)
			continue
		}
		if got := parseCPUPolicy(policy); got != expected {
			t.Errorf("%s parsed as %v, want %v", name, got, expected)
		}
	}
}

func TestParseCPUPlacementPolicy_CoversEveryNUMAPolicy(t *testing.T) {
	want := map[zconfig.NumaPolicy]types.CPUNUMAPolicy{
		zconfig.NumaPolicy_NUMA_POLICY_UNSPECIFIED:      types.CPUNUMAPolicyUnspecified,
		zconfig.NumaPolicy_NUMA_POLICY_NONE:             types.CPUNUMAPolicyNone,
		zconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT:      types.CPUNUMAPolicyBestEffort,
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
