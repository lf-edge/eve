// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// parseCPUPlacementPolicy translates the controller's CPU placement intent into
// the device-internal vocabulary. Unknown enum values from a newer controller
// map to "unspecified" and are therefore treated as no preference rather than
// being rejected.
func parseCPUPlacementPolicy(fr *zconfig.VmConfig) types.CPUPlacementPolicy {
	if fr == nil {
		return types.CPUPlacementPolicy{}
	}
	return types.CPUPlacementPolicy{
		Policy:           parseCPUPolicy(fr.GetCpuPolicy()),
		FullPCPUsOnly:    fr.GetFullPcpusOnly(),
		ThreadsPerCore:   fr.GetThreadsPerCore(),
		NUMAPolicy:       parseCPUNUMAPolicy(fr.GetNumaPolicy()),
		IOPlacement:      parseCPUIOPlacement(fr.GetIoPlacement()),
		IsolationTier:    parseCPUIsolationTier(fr.GetIsolationTier()),
		DisruptionPolicy: parseCPUDisruptionPolicy(fr.GetDisruptionPolicy()),
	}
}

// cpusPinnedFromPolicy derives the legacy CPUsPinned flag. A policy, when the
// controller sends one, is authoritative; otherwise the legacy pin_cpu flag
// decides, so an older controller keeps behaving exactly as before.
//
// This is also what makes a dedicated policy self-sufficient: the workload no
// longer has to set pin_cpu as well for its CPUs to actually be pinned.
func cpusPinnedFromPolicy(p types.CPUPlacementPolicy, legacyPinCPU bool) bool {
	switch p.Policy {
	case types.CPUPolicyDedicated:
		return true
	case types.CPUPolicyShared:
		return false
	default:
		return legacyPinCPU
	}
}

func parseCPUPolicy(p zconfig.CpuPolicy) types.CPUPolicy {
	switch p {
	case zconfig.CpuPolicy_CPU_POLICY_SHARED:
		return types.CPUPolicyShared
	case zconfig.CpuPolicy_CPU_POLICY_DEDICATED:
		return types.CPUPolicyDedicated
	}
	return types.CPUPolicyUnspecified
}

func parseCPUNUMAPolicy(p zconfig.NumaPolicy) types.CPUNUMAPolicy {
	switch p {
	case zconfig.NumaPolicy_NUMA_POLICY_NONE:
		return types.CPUNUMAPolicyNone
	case zconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT:
		return types.CPUNUMAPolicyBestEffort
	case zconfig.NumaPolicy_NUMA_POLICY_RESTRICTED:
		return types.CPUNUMAPolicyRestricted
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

func parseCPUIsolationTier(t zconfig.IsolationTier) types.CPUIsolationTier {
	switch t {
	case zconfig.IsolationTier_ISOLATION_TIER_NONE:
		return types.CPUIsolationTierNone
	case zconfig.IsolationTier_ISOLATION_TIER_SOFT:
		return types.CPUIsolationTierSoft
	case zconfig.IsolationTier_ISOLATION_TIER_HARD:
		return types.CPUIsolationTierHard
	}
	return types.CPUIsolationTierUnspecified
}

func parseCPUDisruptionPolicy(p zconfig.DisruptionPolicy) types.CPUDisruptionPolicy {
	switch p {
	case zconfig.DisruptionPolicy_DISRUPTION_POLICY_ALLOW:
		return types.CPUDisruptionPolicyAllow
	case zconfig.DisruptionPolicy_DISRUPTION_POLICY_PROTECT:
		return types.CPUDisruptionPolicyProtect
	}
	return types.CPUDisruptionPolicyUnspecified
}
