// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// readIsolatedCPUs returns the logical CPUs the running kernel isolates.
//
// Read from sysfs rather than from the kernel command line, so it reports what
// the kernel is actually doing. It cannot change without a reboot, so it is read
// once and kept.
func readIsolatedCPUs() []cputopology.LCPU {
	isolated, _, _ := hardware.IsolatedCPUSets()
	out := make([]cputopology.LCPU, 0, len(isolated))
	for _, cpu := range isolated {
		out = append(out, cputopology.LCPU(cpu))
	}
	return out
}

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
// published type.
func cpuPoolStatus(placer *cpuallocator.Placer) types.CPUPoolStatus {
	var out types.CPUPoolStatus
	for _, pool := range placer.PoolUtilization() {
		out.Pools = append(out.Pools, types.CPUPoolUtilization{
			Kind:             cpuPoolKind(pool.Pool),
			CPUs:             lcpusToUint32(pool.CPUs),
			FreeCPUs:         lcpusToUint32(pool.FreeCPUs),
			TotalThreads:     pool.TotalThreads,
			AllocatedThreads: pool.AllocatedThreads,
			FreeThreads:      pool.FreeThreads,
			TotalCores:       pool.TotalCores,
			FreeWholeCores:   pool.FreeWholeCores,
		})
	}
	return out
}

func lcpusToUint32(cpus []cputopology.LCPU) []uint32 {
	if len(cpus) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(cpus))
	for _, cpu := range cpus {
		out = append(out, uint32(cpu))
	}
	return out
}

// publishCPUPoolStatus recomputes the node CPU pool report and publishes it.
//
// The report is derived state, so it is recomputed rather than incrementally
// maintained, and this is called from every path that touches the allocator.
// pubsub drops a republication that is byte-identical to the last one, so
// calling it on a path that changed nothing costs nothing.
func publishCPUPoolStatus(ctx *domainContext) {
	if ctx.placer == nil || ctx.pubCPUPoolStatus == nil {
		return
	}
	status := cpuPoolStatus(ctx.placer)
	if err := ctx.pubCPUPoolStatus.Publish(status.Key(), status); err != nil {
		log.Errorf("publishCPUPoolStatus failed: %v", err)
	}
}
