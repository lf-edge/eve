// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// Machine-parseable error codes reported alongside the free-text description in
// ErrorInfo.error_code, so a controller can react programmatically without
// parsing prose. Codes are namespaced by domain and are part of the published
// contract: once shipped, a code's meaning must not change. New conditions get
// new codes rather than redefining existing ones.
const (
	// ErrorCodeCPUPlacementInsufficient means the node does not have enough
	// CPUs of the required kind for this workload, in any arrangement.
	ErrorCodeCPUPlacementInsufficient = "cpu.placement.insufficient"
	// ErrorCodeCPUPlacementNeedsRepack means a placement exists, but only by
	// moving workloads that are already running.
	ErrorCodeCPUPlacementNeedsRepack = "cpu.placement.needs_repack"
	// ErrorCodeCPUPlacementDegraded would mean the workload is placed and
	// running, but not at the best achievable quality.
	//
	// Reserved: nothing emits it. The running-but-improvable case is reported as
	// ErrorCodeCPUPlacementNeedsRepack, which names the reason a better
	// placement is not taken (it would restart running workloads). The code is
	// kept because "degraded" is where a fragmentation advisory about a resource
	// other than cores would land, and a controller must not be given a second
	// meaning for a code it already handles.
	ErrorCodeCPUPlacementDegraded = "cpu.placement.degraded"
	// ErrorCodeCPUPolicyOddVCPU means whole-core-SMT was requested with an odd
	// vCPU count, which no arrangement of two-thread cores can satisfy.
	ErrorCodeCPUPolicyOddVCPU = "cpu.policy.odd_vcpu"
	// ErrorCodeCPUIsolationTierUnavailable means the requested isolation tier
	// is not supported by this node.
	ErrorCodeCPUIsolationTierUnavailable = "cpu.isolation.tier_unavailable"
	// ErrorCodeCPUPolicyInvalid means the placement policy is malformed or
	// self-contradictory.
	ErrorCodeCPUPolicyInvalid = "cpu.policy.invalid"
	// ErrorCodeCPUTopologyUnsupported means whole-physical-core placement was
	// requested but the active hypervisor cannot bind vCPUs to named host CPUs
	// or expose the resulting guest topology, so the request cannot be honored
	// on this node no matter how many CPUs are free.
	ErrorCodeCPUTopologyUnsupported = "cpu.topology.unsupported"
)
