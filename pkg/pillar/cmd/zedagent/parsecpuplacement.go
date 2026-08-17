// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// parseCPUPlacementPolicy translates the controller's CPU placement intent into
// the device-internal vocabulary: cpu_policy picks the pool, pin_cpu whether
// EVE pins each vCPU, and each field keeps its meaning whatever the others say.
// A combination EVE does not serve is refused later, by domainmgr, not
// reinterpreted here.
//
// The one exception is legacy: a controller that predates cpu_policy sends only
// pin_cpu. That is resolved here (types.CPUPlacementPolicy.ResolveLegacy), so
// nothing downstream sees an unspecified policy.
//
// Unknown enum values from a newer controller map to "unspecified". That is
// safe only because a controller sends these fields to a device that
// advertises it places CPUs (OptionalCapabilities.cpu_placement).
func parseCPUPlacementPolicy(fr *zconfig.VmConfig) types.CPUPlacementPolicy {
	if fr == nil {
		return types.CPUPlacementPolicy{Policy: types.CPUPolicyHousekeeping}
	}
	p := types.CPUPlacementPolicy{
		Policy:         parseCPUPolicy(fr.GetCpuPolicy()),
		Pinned:         fr.GetPinCpu(),
		FullPCPUsOnly:  fr.GetFullPcpusOnly(),
		ThreadsPerCore: fr.GetThreadsPerCore(),
		NUMAPolicy:     parseCPUNUMAPolicy(fr.GetNumaPolicy()),
		IOPlacement:    parseCPUIOPlacement(fr.GetIoPlacement()),
	}
	return p.ResolveLegacy(fr.GetPinCpu(),
		fr.GetVirtualizationMode() == zconfig.VmMode_NOHYPER)
}

func parseCPUPolicy(p zconfig.CpuPolicy) types.CPUPolicy {
	switch p {
	case zconfig.CpuPolicy_CPU_POLICY_HOUSEKEEPING:
		return types.CPUPolicyHousekeeping
	case zconfig.CpuPolicy_CPU_POLICY_DEDICATED:
		return types.CPUPolicyDedicated
	case zconfig.CpuPolicy_CPU_POLICY_ISOLATED:
		return types.CPUPolicyIsolated
	}
	return types.CPUPolicyUnspecified
}

func parseCPUNUMAPolicy(p zconfig.NumaPolicy) types.CPUNUMAPolicy {
	switch p {
	case zconfig.NumaPolicy_NUMA_POLICY_NONE:
		return types.CPUNUMAPolicyNone
	case zconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT:
		return types.CPUNUMAPolicyBestEffort
	case zconfig.NumaPolicy_NUMA_POLICY_SINGLE_NUMA_NODE:
		return types.CPUNUMAPolicySingleNode
	}
	return types.CPUNUMAPolicyUnspecified
}

func parseCPUIOPlacement(p zconfig.IoPlacement) types.CPUIOPlacement {
	switch p {
	case zconfig.IoPlacement_IO_PLACEMENT_DEDICATED:
		return types.CPUIOPlacementDedicated
	case zconfig.IoPlacement_IO_PLACEMENT_HOUSEKEEPING:
		return types.CPUIOPlacementHousekeeping
	}
	return types.CPUIOPlacementUnspecified
}
