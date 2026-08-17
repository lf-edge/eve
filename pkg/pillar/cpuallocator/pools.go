// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
)

// CPUPool names one partition of the node's logical CPUs. The pools are
// disjoint and together cover every CPU, as the API defines them, so a consumer
// can add them up.
type CPUPool int

const (
	// PoolHousekeeping is every logical CPU the kernel does not isolate and no
	// workload holds exclusively: the CPUs reserved for EVE itself plus whatever
	// is left over, which is where every workload that did not ask for dedicated
	// placement runs.
	PoolHousekeeping CPUPool = iota
	// PoolDedicated is every logical CPU outside the isolated set held
	// exclusively by some workload, including SMT siblings parked idle by a
	// one-thread-per-core request.
	PoolDedicated
	// PoolIsolated is the set the running kernel isolates (isolcpus), whether
	// free or held by a workload, so a consumer can see how much shielded
	// capacity exists and how much of it is already taken.
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
	// workloads the node can take. Single-thread cores count too, as the API
	// defines the field, though a whole-core-smt request cannot use them; a
	// consumer that needs two-thread cores finds them from the topology.
	FreeWholeCores uint32
}

// PoolUtilization reports every CPU pool of the node and how much of each is
// left, for the node-level "will it fit?" report.
//
// The kernel-isolated set comes from the placer rather than from the caller: the
// placer withholds those CPUs from ordinary placement, so a report built from a
// second, independently supplied set could describe capacity as available that
// placement would refuse -- and the report exists precisely to be trusted on
// that question.
func (p *Placer) PoolUtilization() []PoolUtilization {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.degraded {
		// The pools would describe cores that do not exist.
		return nil
	}

	dedicated := p.dedicatedLookup()
	// free means "could still be given to a workload asking for dedicated
	// placement": the same exclusions Allocate applies. A kernel-isolated CPU is
	// only ever in the isolated pool, so the pool it is free in is the one a
	// workload requesting isolation draws from. Neither thread of a core only
	// partly isolated is free: such a core serves no placement.
	isFree := func(c cputopology.LCPU) bool {
		pc := p.topo.ByLCPU[c]
		return !dedicated[c] && uint32(c) >= p.numReservedForEVE &&
			(p.coreIsIsolated(pc) || !p.coreTouchesIsolated(pc))
	}

	var housekeeping, dedicatedCPUs, isolatedCPUs []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		switch {
		case p.isolated[c]:
			isolatedCPUs = append(isolatedCPUs, c)
		case dedicated[c]:
			dedicatedCPUs = append(dedicatedCPUs, c)
		default:
			housekeeping = append(housekeeping, c)
		}
	}

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
