// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// cpuPoolKind maps an allocator pool onto the published vocabulary.
func cpuPoolKind(pool cpuallocator.CPUPool) types.CPUPoolKind {
	switch pool {
	case cpuallocator.PoolHousekeeping:
		return types.CPUPoolKindHousekeeping
	case cpuallocator.PoolDedicated:
		return types.CPUPoolKindDedicated
	case cpuallocator.PoolIsolated:
		return types.CPUPoolKindIsolated
	}
	// A pool with real CPUs in it and no kind reads on the wire as capacity
	// nobody can account for, so a newly added pool must not slip out unlabelled.
	log.Errorf("cpuPoolKind: allocator pool %d has no published kind", pool)
	return types.CPUPoolKindUnspecified
}

// cpuPoolStatus projects the allocator's view of the node's CPU pools onto the
// published type. The isolation warnings go on the isolated pool.
func cpuPoolStatus(placer *cpuallocator.Placer,
	isolationWarnings []types.CPUPoolWarning) types.CPUPoolStatus {
	var out types.CPUPoolStatus
	for _, pool := range placer.PoolUtilization() {
		u := types.CPUPoolUtilization{
			Kind:             cpuPoolKind(pool.Pool),
			CPUs:             lcpusToUint32(pool.CPUs),
			FreeCPUs:         lcpusToUint32(pool.FreeCPUs),
			TotalThreads:     pool.TotalThreads,
			AllocatedThreads: pool.AllocatedThreads,
			FreeThreads:      pool.FreeThreads,
			TotalCores:       pool.TotalCores,
			FreeWholeCores:   pool.FreeWholeCores,
		}
		if pool.Pool == cpuallocator.PoolIsolated {
			u.Warnings = isolationWarnings
		}
		out.Pools = append(out.Pools, u)
	}
	return out
}

// isolationWarnings turns the mistakes in the operator's isolcpus into warnings
// on the isolated pool, so the operator is told where they look at the node,
// not only in the device log. The node runs with them: placement keeps every
// workload off the CPUs concerned. They are found once, at startup, and keep
// that time: isolcpus changes only across a reboot, and a stable report is not
// republished.
func isolationWarnings(issues []cpuallocator.IsolationIssue, found time.Time) []types.CPUPoolWarning {
	var out []types.CPUPoolWarning
	for _, issue := range issues {
		kind := types.CPUPoolIssuePartialCore
		if issue.Kind == cpuallocator.IsolationIssueReservedCPUs {
			kind = types.CPUPoolIssueReservedCPUs
		}
		out = append(out, types.CPUPoolWarning{
			Issue: kind,
			ErrorDescription: types.ErrorDescription{
				Error:         issue.Message,
				ErrorTime:     found,
				ErrorSeverity: types.ErrorSeverityWarning,
				ErrorRetryCondition: "Correct isolcpus on the kernel command line " +
					"(for example in /config/grub.cfg) and reboot the node",
			},
		})
	}
	return out
}
