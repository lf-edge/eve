// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// cpuPoolStatus is the node's CPU pool report: the placer's pools, with the
// isolation warnings on the isolated pool.
func cpuPoolStatus(placer *cpuallocator.Placer,
	isolationWarnings []types.CPUPoolWarning) types.CPUPoolStatus {
	pools := placer.Pools()
	for i := range pools {
		if pools[i].Kind == types.CPUPoolKindIsolated {
			pools[i].Warnings = isolationWarnings
		}
	}
	return types.CPUPoolStatus{Pools: pools}
}

// isolationWarnings turns the mistakes in the operator's isolcpus into warnings
// on the isolated pool, so the operator is told where they look at the node,
// not only in the device log. The node runs with them: placement keeps every
// workload off the CPUs concerned. They are found once, at startup, and keep
// that time: isolcpus changes only across a reboot, and a stable report is not
// republished.
func isolationWarnings(placer *cpuallocator.Placer, found time.Time) []types.CPUPoolWarning {
	warnings := placer.IsolationIssues()
	for i := range warnings {
		warnings[i].ErrorTime = found
	}
	return warnings
}
