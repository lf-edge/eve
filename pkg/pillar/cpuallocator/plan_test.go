// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"fmt"
	"testing"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
)

// permutationsOf returns every ordering of the requests. A single reversal is not
// enough to pin order-independence down: it exercises one of n! arrival orders,
// and the orders that expose a partial sort key are usually not that one.
func permutationsOf(requests []Request) [][]Request {
	if len(requests) <= 1 {
		return [][]Request{append([]Request{}, requests...)}
	}
	var out [][]Request
	for i := range requests {
		rest := make([]Request, 0, len(requests)-1)
		rest = append(rest, requests[:i]...)
		rest = append(rest, requests[i+1:]...)
		for _, tail := range permutationsOf(rest) {
			out = append(out, append([]Request{requests[i]}, tail...))
		}
	}
	return out
}

// samePlan reports the first difference between two plans, or "" if they agree.
func samePlan(want, got map[uuid.UUID]Result) string {
	if len(want) != len(got) {
		return fmt.Sprintf("plans differ in size: %d vs %d", len(want), len(got))
	}
	for id, w := range want {
		g, ok := got[id]
		if !ok {
			return fmt.Sprintf("workload %s missing", id)
		}
		if w.Status != g.Status {
			return fmt.Sprintf("%s: status %v vs %v", id, w.Status, g.Status)
		}
		if w.Status != Success {
			continue
		}
		if !equalLCPUs(w.Assignment.OrderedHostCPUs, g.Assignment.OrderedHostCPUs) {
			return fmt.Sprintf("%s: vCPUs %v vs %v", id,
				w.Assignment.OrderedHostCPUs, g.Assignment.OrderedHostCPUs)
		}
		if !equalLCPUs(w.Assignment.ParkedCPUs, g.Assignment.ParkedCPUs) {
			return fmt.Sprintf("%s: parked %v vs %v", id,
				w.Assignment.ParkedCPUs, g.Assignment.ParkedCPUs)
		}
	}
	return ""
}

// Planning the same set of workloads must produce the same assignment whatever
// order the requests arrive in. This is the property that removes the boot-order
// race: allocating incrementally, whoever activated first won the scarce cores.
func TestPlan_IsOrderIndependent(t *testing.T) {
	requests := []Request{
		{UUID: u("smt"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
		{UUID: u("ope"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
		{UUID: u("smt2"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
	}

	orders := permutationsOf(requests)
	reference := mustPlacer(t, twoSocketTopo(), 0).Plan(orders[0])
	for _, order := range orders[1:] {
		got := mustPlacer(t, twoSocketTopo(), 0).Plan(order)
		if diff := samePlan(reference, got); diff != "" {
			ids := make([]string, 0, len(order))
			for _, r := range order {
				ids = append(ids, r.UUID.String())
			}
			t.Errorf("plan depends on arrival order %v: %s", ids, diff)
		}
	}
}

// Two workloads identical in mode and size are ordered by nothing but their
// identity, and the sort's third key is the only thing that makes that order
// total. Without it Go's unstable sort leaves them in demand-set order, so two
// equally shaped apps swap NUMA nodes depending on which status arrived first --
// a different layout after every reboot, for no reason the operator can see.
func TestPlan_EquallyShapedWorkloadsAreOrderedByIdentity(t *testing.T) {
	// One core per NUMA node, so only one of the two can have node 0 and the
	// choice between them is decided purely by the tie-break.
	requests := []Request{
		{UUID: u("twin-a"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
		{UUID: u("twin-b"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
	}
	forward := mustPlacer(t, twoNodesOneCoreEach(), 0).Plan(requests)
	backward := mustPlacer(t, twoNodesOneCoreEach(), 0).Plan(
		[]Request{requests[1], requests[0]})

	for _, id := range []uuid.UUID{requests[0].UUID, requests[1].UUID} {
		if forward[id].Status != Success {
			t.Fatalf("%s: want Success, got %v (%s)", id, forward[id].Status, forward[id].Message)
		}
	}
	if diff := samePlan(forward, backward); diff != "" {
		t.Errorf("equally shaped workloads swapped places with the arrival order: %s", diff)
	}
	// They must genuinely be competing for one node, or the tie-break is untested.
	nodesA := forward[requests[0].UUID].Assignment.NUMANodes
	nodesB := forward[requests[1].UUID].Assignment.NUMANodes
	if len(nodesA) != 1 || len(nodesB) != 1 || nodesA[0] == nodesB[0] {
		t.Fatalf("the twins must contend for one node, got %v and %v", nodesA, nodesB)
	}
}

// The tightest-constrained workload must be placed first, so a flexible one
// cannot take the only core that the constrained one could have used. On a
// topology with a single SMT-capable core, an interleaved plan that served the
// one-per-core request first would leave whole-core-SMT unsatisfiable.
func TestPlan_TightestConstraintFirst(t *testing.T) {
	// One SMT core (2 threads) plus two single-thread cores.
	infos := []cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0}, // sibling of 0
		{LCore: 2, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 3, Socket: 0, CoreID: 2, NUMA: 0, L3ID: 0},
	}
	plan := mustPlacer(t, cputopology.BuildTopology(infos), 0).Plan([]Request{
		// Deliberately listed with the flexible request first.
		{UUID: u("flexible"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
		{UUID: u("needs-smt"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
	})

	smt := plan[u("needs-smt")]
	if smt.Status != Success {
		t.Fatalf("whole-core-smt must be placed first and succeed, got %v (%s)",
			smt.Status, smt.Message)
	}
	// It must have taken the one two-thread core.
	if !equalLCPUs(smt.Assignment.OrderedHostCPUs, []cputopology.LCPU{0, 1}) {
		t.Errorf("whole-core-smt got %v, want the SMT core [0 1]",
			smt.Assignment.OrderedHostCPUs)
	}
	if flexible := plan[u("flexible")]; flexible.Status != Success {
		t.Errorf("the flexible workload should still fit on a single-thread core, got %v (%s)",
			flexible.Status, flexible.Message)
	}
}

// Planned workloads must never be given overlapping CPUs, including the
// siblings parked by a one-per-core request.
func TestPlan_AssignmentsAreDisjoint(t *testing.T) {
	plan := mustPlacer(t, twoSocketTopo(), 0).Plan([]Request{
		{UUID: u("a"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
		{UUID: u("b"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
		{UUID: u("c"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
	})

	owner := map[cputopology.LCPU]uuid.UUID{}
	for id, result := range plan {
		if result.Status != Success {
			continue
		}
		all := append(append([]cputopology.LCPU{}, result.Assignment.OrderedHostCPUs...),
			result.Assignment.ParkedCPUs...)
		for _, cpu := range all {
			if other, taken := owner[cpu]; taken {
				t.Fatalf("CPU %d assigned to both %s and %s", cpu, other, id)
			}
			owner[cpu] = id
		}
	}
}

// A workload that cannot be placed must be reported as such without preventing
// the others from being placed: one unsatisfiable request is not a reason to
// leave the whole node unallocated.
func TestPlan_UnsatisfiableRequestDoesNotBlockOthers(t *testing.T) {
	plan := mustPlacer(t, twoSocketTopo(), 0).Plan([]Request{
		{UUID: u("fits"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
		{UUID: u("huge"), NumVCPUs: 64, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
	})

	if got := plan[u("fits")].Status; got != Success {
		t.Errorf("the satisfiable request must still be placed, got %v", got)
	}
	if got := plan[u("huge")].Status; got == Success {
		t.Error("a request for more cores than exist must not succeed")
	}
}

// applyPlan reserves every successfully planned assignment, as domainmgr does
// when the workloads actually start. Reserve rejecting anything would itself mean
// the plan handed one CPU to two workloads.
func applyPlan(t *testing.T, placer *Placer, plan map[uuid.UUID]Result) {
	t.Helper()
	for id, result := range plan {
		if result.Status != Success {
			continue
		}
		var cpus []uint32
		for _, c := range result.Assignment.OrderedHostCPUs {
			cpus = append(cpus, uint32(c))
		}
		for _, c := range result.Assignment.ParkedCPUs {
			cpus = append(cpus, uint32(c))
		}
		if err := placer.Reserve(id, cpus); err != nil {
			t.Fatalf("applying the plan for %s: %v", id, err)
		}
	}
}

// Adding a workload must not move the ones already running. Re-planning starts
// from an empty slate, so nothing stops the allocator from producing a better
// global layout that relocates a running VM -- and relocating it would mean
// restarting it. What prevents that is the ordering: the new workload is less
// constrained than the running ones, so it is placed after them and takes only
// what is left. This test fails if that ordering is weakened.
func TestPlan_AddingAWorkloadDoesNotMoveRunningOnes(t *testing.T) {
	running := []Request{
		{UUID: u("a"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort},
		{UUID: u("b"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
	}
	placer := mustPlacer(t, twoSocketTopo(), 0)
	before := placer.Plan(running)
	applyPlan(t, placer, before)

	newcomer := Request{UUID: u("c"), NumVCPUs: 3, Mode: ModeShared}
	after := placer.Plan(append(append([]Request{}, running...), newcomer))

	for _, r := range running {
		want, got := before[r.UUID], after[r.UUID]
		if want.Status != Success {
			t.Fatalf("%s was not placed to begin with: %v (%s)", r.UUID, want.Status, want.Message)
		}
		if got.Status != Success {
			t.Errorf("%s lost its placement when %s appeared: %v (%s)",
				r.UUID, newcomer.UUID, got.Status, got.Message)
			continue
		}
		if !equalLCPUs(want.Assignment.OrderedHostCPUs, got.Assignment.OrderedHostCPUs) {
			t.Errorf("%s would have to be restarted: vCPUs moved %v -> %v", r.UUID,
				want.Assignment.OrderedHostCPUs, got.Assignment.OrderedHostCPUs)
		}
		if !equalLCPUs(want.Assignment.ParkedCPUs, got.Assignment.ParkedCPUs) {
			t.Errorf("%s: parked siblings moved %v -> %v", r.UUID,
				want.Assignment.ParkedCPUs, got.Assignment.ParkedCPUs)
		}
	}
	if c := after[newcomer.UUID]; c.Status != Success {
		t.Errorf("the new workload must still be placed, got %v (%s)", c.Status, c.Message)
	}
}

// A thread-granular shortage must not report core counts. domainmgr decides
// whether a refusal can clear by freeing whole cores from these numbers, and a
// shared request is not measured in cores at all -- a nonzero count here would
// send it down the wrong retry path.
func TestPlan_SharedShortageReportsNoCoreCounts(t *testing.T) {
	plan := mustPlacer(t, twoCoresSMT2(), 0).Plan([]Request{
		{UUID: u("greedy"), NumVCPUs: 64, Mode: ModeShared},
	})
	result := plan[u("greedy")]
	if result.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", result.Status, result.Message)
	}
	if result.CoresNeeded != 0 || result.CoresFree != 0 {
		t.Errorf("a thread-granular shortage is not counted in cores, got %d/%d",
			result.CoresNeeded, result.CoresFree)
	}
}

// Reserved CPUs backing EVE's own housekeeping must stay out of every plan.
func TestPlan_HonorsReservedCPUs(t *testing.T) {
	const reserved = 2
	plan := mustPlacer(t, twoSocketTopo(), reserved).Plan([]Request{
		{UUID: u("a"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMABestEffort},
	})
	result := plan[u("a")]
	if result.Status != Success {
		t.Fatalf("want Success, got %v (%s)", result.Status, result.Message)
	}
	for _, cpu := range result.Assignment.OrderedHostCPUs {
		if uint32(cpu) < reserved {
			t.Errorf("plan used reserved CPU %d", cpu)
		}
	}
}

// Thread-granular workloads must appear in the plan too: they take CPUs
// exclusively, so a caller deriving a housekeeping set from the plan has to see
// them, and they must never be planned onto a whole-core workload's cores.
func TestPlan_IncludesThreadGranularWorkloads(t *testing.T) {
	plan := mustPlacer(t, twoSocketTopo(), 0).Plan([]Request{
		{UUID: u("wholecore"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal},
		{UUID: u("legacy"), NumVCPUs: 3, Mode: ModeShared},
	})

	legacy := plan[u("legacy")]
	if legacy.Status != Success || len(legacy.Assignment.OrderedHostCPUs) != 3 {
		t.Fatalf("thread-granular workload must be planned, got %v (%s)",
			legacy.Status, legacy.Message)
	}
	whole := plan[u("wholecore")]
	if whole.Status != Success {
		t.Fatalf("whole-core workload must still be planned, got %v (%s)",
			whole.Status, whole.Message)
	}
	taken := map[cputopology.LCPU]bool{}
	for _, cpu := range whole.Assignment.OrderedHostCPUs {
		taken[cpu] = true
	}
	for _, cpu := range legacy.Assignment.OrderedHostCPUs {
		if taken[cpu] {
			t.Errorf("thread-granular plan overlaps a whole-core one at cpu %d", cpu)
		}
	}
}

func equalLCPUs(a, b []cputopology.LCPU) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScore_WorseThan(t *testing.T) {
	// NUMA locality dominates cache locality.
	oneNodeTwoL3 := Score{NUMANodes: 1, L3Domains: 2}
	twoNodesOneL3 := Score{NUMANodes: 2, L3Domains: 1}
	if !twoNodesOneL3.WorseThan(oneNodeTwoL3) {
		t.Error("spanning two NUMA nodes must be worse than spanning two L3 domains")
	}
	if oneNodeTwoL3.WorseThan(twoNodesOneL3) {
		t.Error("comparison must not be symmetric")
	}
	// Equal scores are not worse -- this is what stops a placement that merely
	// used different CPU indices from being reported as sub-optimal.
	equal := Score{NUMANodes: 1, L3Domains: 1}
	if equal.WorseThan(equal) {
		t.Error("an equal score must not count as worse")
	}
	// An unrecognised CPU dominates every locality difference: an assignment
	// nobody can interpret must not win a comparison against one that is merely
	// spread out.
	bogus := Score{UnknownCPUs: 1}
	if !bogus.WorseThan(Score{NUMANodes: 4, L3Domains: 4}) {
		t.Error("an unrecognised CPU must outweigh any amount of poor locality")
	}
	if (Score{NUMANodes: 4, L3Domains: 4}).WorseThan(bogus) {
		t.Error("poor locality must not be reported as worse than an uninterpretable CPU")
	}
}

func TestScore_CountsSpannedDomains(t *testing.T) {
	placer := mustPlacer(t, twoSocketTopo(), 0)
	// twoSocketTopo puts each socket in its own NUMA node and L3 domain, so a
	// request that fits in one socket must score 1/1.
	local := placer.Plan([]Request{
		{UUID: u("local"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal},
	})[u("local")]
	if local.Status != Success {
		t.Fatalf("want Success, got %v (%s)", local.Status, local.Message)
	}
	if got := placer.Score(local.Assignment); got != (Score{NUMANodes: 1, L3Domains: 1}) {
		t.Errorf("NUMA-local assignment scored %+v, want 1 node / 1 L3", got)
	}
}

// A placement forced to span the machine must be scored as spanning it: the
// spread is what a sub-optimal-placement report exists to surface, so the counts
// have to grow with it rather than saturate at 1.
func TestScore_CountsEveryDomainSpanned(t *testing.T) {
	placer := mustPlacer(t, twoNodesOneCoreEach(), 0) // one core per node, own L3 each
	spanning := placer.Plan([]Request{
		{UUID: u("spanning"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross},
	})[u("spanning")]
	if spanning.Status != Success {
		t.Fatalf("want Success, got %v (%s)", spanning.Status, spanning.Message)
	}
	want := Score{NUMANodes: 2, L3Domains: 2}
	if got := placer.Score(spanning.Assignment); got != want {
		t.Errorf("spanning assignment scored %+v, want %+v", got, want)
	}
	if !placer.Score(spanning.Assignment).WorseThan(Score{NUMANodes: 1, L3Domains: 1}) {
		t.Error("spanning both nodes must score worse than fitting in one")
	}
}

// Two things Score must never call good: CPUs the topology does not know, and no
// assignment at all. Ignoring unknown CPUs scored a wholly bogus assignment as
// perfect, so a bogus plan made a healthy live placement look sub-optimal and
// demanded a repack; and a nil assignment scoring zero meant an unplaced workload
// silently passed for well placed.
func TestScore_UnknownAndMissingAssignmentsAreNotOptimal(t *testing.T) {
	placer := mustPlacer(t, twoSocketTopo(), 0)
	healthy := Score{NUMANodes: 1, L3Domains: 1}

	bogus := placer.Score(&Assignment{OrderedHostCPUs: lcpus(200, 201)})
	if bogus.UnknownCPUs != 2 {
		t.Errorf("want both unknown CPUs counted, got %+v", bogus)
	}
	if !bogus.WorseThan(healthy) {
		t.Errorf("an assignment of CPUs this host does not have must be worse than a real one, got %+v", bogus)
	}
	if healthy.WorseThan(bogus) {
		t.Error("a healthy placement must not be reported as worse than a bogus one")
	}

	missing := placer.Score(nil)
	if !missing.WorseThan(healthy) {
		t.Errorf("no assignment must score worse than any real one, got %+v", missing)
	}
	// Nothing may be worse than "not placed", including itself: the comparison
	// must never conclude a real placement should be replaced by nothing.
	if healthy.WorseThan(missing) || missing.WorseThan(missing) {
		t.Error("nothing may be reported as worse than a missing assignment")
	}
}
