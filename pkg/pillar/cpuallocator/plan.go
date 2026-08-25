// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"fmt"
	"math"
	"sort"

	uuid "github.com/satori/go.uuid"
)

// Plan computes placement for a whole set of workloads at once and returns one
// result per workload.
//
// Planning the set together, rather than allocating for each workload as it
// happens to activate, is what makes placement independent of order. Allocating
// incrementally meant whichever workload activated first won the scarce cores:
// a flexible workload could take the only SMT-capable core, leaving a workload
// that *needs* one unplaceable, and the same set of apps could land differently
// on each boot. Here the requests are ordered by how constrained they are --
// the workloads with the fewest possible placements first -- so the outcome
// depends only on the set itself.
//
// Plan does not mutate the placer: it neither reserves nor frees anything. The
// caller applies a planned assignment with Reserve when the workload actually
// starts, which is what lets a workload that has not started yet -- or starts
// late -- still claim the CPUs the plan set aside for it.
func (p *Placer) Plan(requests []Request) map[uuid.UUID]Result {
	ordered := make([]Request, len(requests))
	copy(ordered, requests)
	sort.Slice(ordered, func(i, j int) bool {
		if a, b := constraintRank(ordered[i]), constraintRank(ordered[j]); a != b {
			return a < b
		}
		// Among equally constrained workloads the larger one is harder to fit,
		// so place it while there is still room.
		if ordered[i].NumVCPUs != ordered[j].NumVCPUs {
			return ordered[i].NumVCPUs > ordered[j].NumVCPUs
		}
		// Tie-break on identity so the order is total and therefore stable.
		return ordered[i].UUID.String() < ordered[j].UUID.String()
	})

	// Plan from an empty slate so the result is a function of the request set
	// alone, not of whatever is allocated at this moment.
	scratch := newPlacer(p.topo, p.numReservedForEVE, p.IsolatedCPUs())
	plan := make(map[uuid.UUID]Result, len(ordered))
	for _, request := range ordered {
		// One unplaceable workload must not stop the rest from being placed.
		plan[request.UUID] = scratch.place(request)
	}
	return plan
}

// place runs one planned request, routing thread-granular ones to the shared
// allocator. Those are planned as well, even though nothing applies a planned
// shared assignment, because they still take CPUs exclusively: a caller
// deriving a CPU set that no pinned workload will ever occupy has to know about
// them too.
func (p *Placer) place(r Request) Result {
	if r.Mode != ModeShared {
		return p.Allocate(r)
	}
	cpus, err := p.AllocateShared(r.UUID, r.NumVCPUs)
	if err != nil {
		return Result{Status: Insufficient, Message: err.Error()}
	}
	return Result{Status: Success, Assignment: &Assignment{OrderedHostCPUs: cpus}}
}

// constraintRank orders workloads from fewest possible placements to most.
// whole-core-SMT is the most constrained: it can only use a core that actually
// has two hardware threads, and on a hybrid or SMT-disabled machine most cores
// do not. one-per-core will take any physical core. Anything else is
// thread-granular and can go almost anywhere.
func constraintRank(r Request) int {
	switch r.Mode {
	case ModeWholeCoreSMT:
		return 0
	case ModeOnePerCore:
		return 1
	default:
		return 2
	}
}

// String implements fmt.Stringer so an outcome can be reported in a status or a
// diagnostic without every caller mapping the values itself.
func (s Status) String() string {
	switch s {
	case StatusUnspecified:
		return "unspecified"
	case Success:
		return "success"
	case NeedsRebalance:
		return "needs-rebalance"
	case Insufficient:
		return "insufficient"
	case InvalidRequest:
		return "invalid-request"
	}
	return fmt.Sprintf("unknown(%d)", int(s))
}

// Score ranks an assignment by placement quality, lower being better. It is
// compared lexicographically: unrecognised CPUs dominate, then NUMA locality,
// then cache locality.
//
// Deliberately absent is which CPU indices were used. Many assignments share the
// best score -- any whole core in the right NUMA node and L3 domain is as good as
// any other -- so a placement that differs only in indices is not worse. Treating
// index choice as quality would make a workload look mis-placed simply because
// its first-choice CPUs were taken, and would demand pointless restarts.
type Score struct {
	// UnknownCPUs is how many of the assignment's host CPUs the topology does
	// not have. It dominates because such an assignment cannot be judged at all:
	// skipping the CPUs silently scored a wholly bogus assignment as perfect
	// {0,0}, which made a healthy live placement compare as worse than a bogus
	// plan and produced a repack recommendation derived from nothing.
	UnknownCPUs int
	// NUMANodes is how many NUMA nodes the assignment spans. Spanning nodes
	// costs cross-socket memory latency on every access.
	NUMANodes int
	// L3Domains is how many last-level caches it spans.
	L3Domains int
}

// WorseThan reports whether this score is strictly worse than another.
func (s Score) WorseThan(other Score) bool {
	if s.UnknownCPUs != other.UnknownCPUs {
		return s.UnknownCPUs > other.UnknownCPUs
	}
	if s.NUMANodes != other.NUMANodes {
		return s.NUMANodes > other.NUMANodes
	}
	return s.L3Domains > other.L3Domains
}

// worstScore is the score of something that cannot be evaluated at all. It is
// worse than every real score, so a comparison against it can only ever conclude
// "the alternative is at least as good".
var worstScore = Score{UnknownCPUs: math.MaxInt, NUMANodes: math.MaxInt, L3Domains: math.MaxInt}

// Score computes the quality of an assignment against the topology.
//
// A nil assignment scores the worst possible value, not the best. "Nothing is
// placed" must never compare as at least as good as a real placement, or a
// workload with no assignment would silently pass an is-this-good-enough check
// instead of being reported as unplaced.
func (p *Placer) Score(a *Assignment) Score {
	if a == nil {
		return worstScore
	}
	unknown := 0
	numaNodes := map[uint]bool{}
	l3Domains := map[uint]bool{}
	// A core whose L3 id the kernel does not expose counts as a cache domain of
	// its own. Grouping such cores under their placeholder id would report a
	// workload split across several last-level caches as perfectly cache-local,
	// which is the one direction this score must never err in.
	type physicalCore struct{ socket, core uint }
	unknownL3 := map[physicalCore]bool{}
	for _, cpu := range a.OrderedHostCPUs {
		core, known := p.topo.ByLCPU[cpu]
		if !known {
			unknown++
			continue
		}
		numaNodes[core.NUMA] = true
		if core.L3Unknown {
			unknownL3[physicalCore{core.Socket, core.CoreID}] = true
		} else {
			l3Domains[core.L3ID] = true
		}
	}
	return Score{
		UnknownCPUs: unknown,
		NUMANodes:   len(numaNodes),
		L3Domains:   len(l3Domains) + len(unknownL3),
	}
}
