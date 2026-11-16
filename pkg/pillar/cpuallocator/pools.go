// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Pools reports every CPU pool of the node and how much of each is left, for
// the node-level "will it fit?" report, without warnings (IsolationIssues). The
// pools are disjoint and together cover every CPU, as the API defines them, so
// a consumer can add them up:
//
//   - housekeeping: every CPU the kernel does not isolate and no workload holds,
//     EVE's own and whatever is left over, where every workload without CPUs of
//     its own runs;
//   - dedicated: every CPU outside the isolated set that a workload holds,
//     siblings parked idle by a one-thread-per-core request included;
//   - isolated: the set the running kernel isolates (isolcpus), free or held,
//     so a consumer can see how much shielded capacity exists and how much of
//     it is taken.
//
// The kernel-isolated set comes from the placer rather than from the caller: the
// placer withholds those CPUs from ordinary placement, so a report built from a
// second, independently supplied set could describe capacity as available that
// placement would refuse -- and the report exists precisely to be trusted on
// that question.
func (p *Placer) Pools() []types.CPUPoolUtilization {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.topo.Degraded {
		// The pools would describe cores that do not exist.
		return nil
	}

	holders := p.holdersLocked()
	// free means "could still be given to a workload asking for dedicated
	// placement": the same exclusions Propose applies. A kernel-isolated CPU is
	// only ever in the isolated pool, so the pool it is free in is the one a
	// workload requesting isolation draws from. Neither thread of a core only
	// partly isolated is free: such a core serves no placement.
	isFree := func(c cputopology.LCPU) bool {
		pc := p.topo.CoreOf(c)
		_, held := holders[c]
		return !held && !p.reserved[c] &&
			(p.coreIsIsolated(pc) || !coreTouches(pc, p.isolated))
	}

	var housekeeping, dedicated, isolated []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		_, held := holders[c]
		switch {
		case p.isolated[c]:
			isolated = append(isolated, c)
		case held:
			dedicated = append(dedicated, c)
		default:
			housekeeping = append(housekeeping, c)
		}
	}

	return []types.CPUPoolUtilization{
		p.pool(types.CPUPoolKindHousekeeping, housekeeping, isFree),
		p.pool(types.CPUPoolKindDedicated, dedicated, isFree),
		p.pool(types.CPUPoolKindIsolated, isolated, isFree),
	}
}

// pool summarises one pool. Caller must hold p.mu.
func (p *Placer) pool(kind types.CPUPoolKind, cpus []cputopology.LCPU,
	isFree func(cputopology.LCPU) bool) types.CPUPoolUtilization {
	inPool := lcpuSet(cpus)
	out := types.CPUPoolUtilization{Kind: kind, CPUs: LCPUsToUint32(cpus)}
	for _, c := range cpus {
		if isFree(c) {
			out.FreeCPUs = append(out.FreeCPUs, uint32(c))
		}
	}
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

// LCPUsToUint32 converts CPU ids to the form statuses and reports carry; nil
// for none.
func LCPUsToUint32(cpus []cputopology.LCPU) []uint32 {
	if len(cpus) == 0 {
		return nil
	}
	out := make([]uint32, len(cpus))
	for i, cpu := range cpus {
		out[i] = uint32(cpu)
	}
	return out
}
