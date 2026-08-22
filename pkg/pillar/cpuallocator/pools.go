// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"fmt"
	"sort"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
)

// CPUPool names one partition of the node's logical CPUs.
type CPUPool int

const (
	// PoolHousekeeping is every logical CPU no workload holds exclusively: the
	// CPUs reserved for EVE itself plus whatever is left over, which is where
	// every workload that did not ask for dedicated placement runs.
	PoolHousekeeping CPUPool = iota
	// PoolDedicated is every logical CPU held exclusively by some workload,
	// including SMT siblings parked idle by a one-thread-per-core request.
	PoolDedicated
	// PoolIsolated is the set the running kernel isolates (isolcpus). Unlike the
	// other two it is not part of the partition: it is a kernel fact that cuts
	// across both, reported so a consumer can see how much shielded capacity
	// exists and how much of it is already taken.
	PoolIsolated
)

// String implements fmt.Stringer.
func (p CPUPool) String() string {
	switch p {
	case PoolHousekeeping:
		return "housekeeping"
	case PoolDedicated:
		return "dedicated"
	case PoolIsolated:
		return "isolated"
	default:
		return fmt.Sprintf("CPUPool(%d)", int(p))
	}
}

// PoolUtilization is one pool's extent and how much of it is still available.
//
// Both the sets and the counts are reported because they answer different
// questions, and the whole-core counts are not derivable from a thread count.
// A thread sitting on a core whose sibling is taken cannot be handed to a
// workload that asked for whole physical cores, so "how many threads are free"
// and "how many cores can still be given out whole" are genuinely different
// numbers -- see FreeWholeCores.
type PoolUtilization struct {
	Pool CPUPool
	// CPUs is every logical CPU in this pool, ascending.
	CPUs []cputopology.LCPU
	// FreeCPUs is the subset of CPUs that could still be handed to a workload
	// asking for dedicated placement: not held by any workload, and not part of
	// the range reserved for EVE.
	FreeCPUs []cputopology.LCPU
	// TotalThreads, AllocatedThreads and FreeThreads summarise the sets above.
	TotalThreads     uint32
	AllocatedThreads uint32
	FreeThreads      uint32
	// TotalCores counts the physical cores all of whose SMT siblings are in
	// this pool. A core straddling two pools counts towards neither.
	TotalCores uint32
	// FreeWholeCores counts the physical cores all of whose SMT siblings are
	// free. This -- not FreeThreads -- is what bounds how many more whole-core
	// workloads the node can take.
	FreeWholeCores uint32
}

// PoolUtilization reports every CPU pool of the node and how much of each is
// left, for the node-level "will it fit?" report.
//
// isolated is the set the running kernel isolates, which the allocator does not
// discover for itself: it is a kernel fact read from sysfs by the caller. Ids
// the topology does not know are ignored.
func (p *Placer) PoolUtilization(isolated []cputopology.LCPU) []PoolUtilization {
	p.mu.Lock()
	defer p.mu.Unlock()

	dedicated := p.dedicatedLookup()
	// free means "could still be given to a workload asking for dedicated
	// placement": the same two exclusions Allocate applies.
	isFree := func(c cputopology.LCPU) bool {
		return !dedicated[c] && uint32(c) >= p.numReservedForEVE
	}

	var housekeeping, dedicatedCPUs, isolatedCPUs []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		if dedicated[c] {
			dedicatedCPUs = append(dedicatedCPUs, c)
		} else {
			housekeeping = append(housekeeping, c)
		}
	}
	known := map[cputopology.LCPU]bool{}
	for _, c := range isolated {
		if _, ok := p.topo.ByLCPU[c]; ok && !known[c] {
			known[c] = true
			isolatedCPUs = append(isolatedCPUs, c)
		}
	}
	sort.Slice(isolatedCPUs, func(i, j int) bool { return isolatedCPUs[i] < isolatedCPUs[j] })

	return []PoolUtilization{
		p.poolUtilization(PoolHousekeeping, housekeeping, isFree),
		p.poolUtilization(PoolDedicated, dedicatedCPUs, isFree),
		p.poolUtilization(PoolIsolated, isolatedCPUs, isFree),
	}
}

// poolUtilization summarises one pool. Caller must hold p.mu.
func (p *Placer) poolUtilization(pool CPUPool, cpus []cputopology.LCPU,
	isFree func(cputopology.LCPU) bool) PoolUtilization {

	inPool := make(map[cputopology.LCPU]bool, len(cpus))
	for _, c := range cpus {
		inPool[c] = true
	}
	out := PoolUtilization{
		Pool:         pool,
		CPUs:         cpus,
		TotalThreads: uint32(len(cpus)),
	}
	for _, c := range cpus {
		if isFree(c) {
			out.FreeCPUs = append(out.FreeCPUs, c)
		}
	}
	out.FreeThreads = uint32(len(out.FreeCPUs))
	out.AllocatedThreads = out.TotalThreads - out.FreeThreads

	for i := range p.topo.Cores {
		pc := &p.topo.Cores[i]
		whole, allFree := true, true
		for _, s := range pc.Siblings {
			if !inPool[s] {
				whole = false
				break
			}
			if !isFree(s) {
				allFree = false
			}
		}
		if !whole {
			continue
		}
		out.TotalCores++
		if allFree {
			out.FreeWholeCores++
		}
	}
	return out
}
