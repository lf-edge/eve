// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	uuid "github.com/satori/go.uuid"
)

// smt2Topology builds n physical cores with two SMT siblings each, numbered so
// that core i owns logical CPUs 2i and 2i+1 -- the layout the design doc's
// worked example uses.
func smt2Topology(n uint) *cputopology.Topology {
	var infos []cputopology.CoreInfo
	for core := uint(0); core < n; core++ {
		for thread := uint(0); thread < 2; thread++ {
			infos = append(infos, cputopology.CoreInfo{
				LCore: core*2 + thread, CoreID: core,
			})
		}
	}
	return cputopology.BuildTopology(infos)
}

func lcpus(ids ...uint32) []cputopology.LCPU {
	out := make([]cputopology.LCPU, 0, len(ids))
	for _, id := range ids {
		out = append(out, cputopology.LCPU(id))
	}
	return out
}

func mustReserve(t *testing.T, placer *Placer, id uuid.UUID, cpus ...uint32) {
	t.Helper()
	if err := placer.Reserve(id, cpus); err != nil {
		t.Fatalf("Reserve(%s, %v): %v", id, cpus, err)
	}
}

func poolByKind(t *testing.T, pools []PoolUtilization, want CPUPool) PoolUtilization {
	t.Helper()
	for _, pool := range pools {
		if pool.Pool == want {
			return pool
		}
	}
	t.Fatalf("no %s pool in %v", want, pools)
	return PoolUtilization{}
}

func checkPool(t *testing.T, got, want PoolUtilization) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s pool:\n got %+v\nwant %+v", want.Pool, got, want)
	}
}

// The worked example of the design doc (§9.3): an 8-thread node with CPU 0
// reserved for EVE, app A holding one whole core and app B a single thread.
// Three of the free threads sit on cores that are already partly taken, so the
// node can still hand out exactly one whole core even though four threads are
// free -- which is the entire reason the whole-core counts are reported
// separately from the thread counts.
func TestPoolUtilization_WorkedExample(t *testing.T) {
	placer := newPlacer(smt2Topology(4), 1, lcpus(6, 7))
	mustReserve(t, placer, uuid.NewV5(uuid.NamespaceOID, "A"), 2, 3)
	mustReserve(t, placer, uuid.NewV5(uuid.NamespaceOID, "B"), 4)

	pools := placer.PoolUtilization()
	if len(pools) != 3 {
		t.Fatalf("want a report for every pool, got %d", len(pools))
	}

	checkPool(t, poolByKind(t, pools, PoolHousekeeping), PoolUtilization{
		Pool:     PoolHousekeeping,
		CPUs:     lcpus(0, 1, 5, 6, 7),
		FreeCPUs: lcpus(1, 5),
		// cpu0 is reserved for EVE; cpu6 and cpu7 are kernel-isolated, so they
		// are on offer only to a workload that requests isolation and are not
		// free for an ordinary one. All three count as allocated here.
		TotalThreads: 5, AllocatedThreads: 3, FreeThreads: 2,
		// core0 and core3 lie wholly in the pool; core1 and core2 straddle it.
		TotalCores: 2,
		// Neither is free whole: core0's sibling cpu0 belongs to EVE, and core3
		// is the isolated one.
		FreeWholeCores: 0,
	})

	checkPool(t, poolByKind(t, pools, PoolDedicated), PoolUtilization{
		Pool:         PoolDedicated,
		CPUs:         lcpus(2, 3, 4),
		TotalThreads: 3, AllocatedThreads: 3, FreeThreads: 0,
		// Only core1 lies wholly in the pool; core2's cpu5 does not.
		TotalCores: 1, FreeWholeCores: 0,
	})

	checkPool(t, poolByKind(t, pools, PoolIsolated), PoolUtilization{
		Pool:     PoolIsolated,
		CPUs:     lcpus(6, 7),
		FreeCPUs: lcpus(6, 7),
		// The isolated set overlaps the housekeeping pool rather than
		// partitioning with it: core3 is both free and kernel-isolated.
		TotalThreads: 2, AllocatedThreads: 0, FreeThreads: 2,
		TotalCores: 1, FreeWholeCores: 1,
	})
}

// A free thread count cannot answer "does a whole-core workload fit?". With one
// thread taken on every core there are four free threads and no free core at
// all, so a consumer trusting the thread count would promise capacity that does
// not exist.
func TestPoolUtilization_FreeThreadsAreNotFreeCores(t *testing.T) {
	placer := newPlacer(smt2Topology(4), 0, nil)
	for i, cpu := range []uint32{0, 2, 4, 6} {
		mustReserve(t, placer, uuid.NewV5(uuid.NamespaceOID, string(rune('a'+i))), cpu)
	}
	housekeeping := poolByKind(t, placer.PoolUtilization(), PoolHousekeeping)
	if housekeeping.FreeThreads != 4 {
		t.Errorf("want 4 free threads, got %d", housekeeping.FreeThreads)
	}
	if housekeeping.FreeWholeCores != 0 {
		t.Errorf("every core has a taken sibling, so none is free whole; got %d",
			housekeeping.FreeWholeCores)
	}
	if housekeeping.TotalCores != 0 {
		t.Errorf("every core straddles both pools, so none belongs wholly to "+
			"housekeeping; got %d", housekeeping.TotalCores)
	}
}

// An idle node reports its whole capacity as free, which is what a pre-flight
// "will it fit?" reads.
func TestPoolUtilization_IdleNode(t *testing.T) {
	pools := newPlacer(smt2Topology(4), 2, nil).PoolUtilization()

	housekeeping := poolByKind(t, pools, PoolHousekeeping)
	if housekeeping.TotalThreads != 8 || housekeeping.FreeThreads != 6 {
		t.Errorf("want 8 threads with 6 free, got %d/%d",
			housekeeping.TotalThreads, housekeeping.FreeThreads)
	}
	// Reserving CPUs 0 and 1 withholds core0 whole: a core with a housekeeping
	// sibling is not a core a workload owns exclusively.
	if housekeeping.FreeWholeCores != 3 {
		t.Errorf("want 3 free whole cores, got %d", housekeeping.FreeWholeCores)
	}
	dedicated := poolByKind(t, pools, PoolDedicated)
	if dedicated.TotalThreads != 0 || dedicated.CPUs != nil {
		t.Errorf("nothing is dedicated, got %+v", dedicated)
	}
}

// Only the reported free whole-core count, never the free thread count, should
// agree with what the allocator will actually hand out.
func TestPoolUtilization_MatchesWhatAllocateGrants(t *testing.T) {
	placer := newPlacer(smt2Topology(4), 1, nil)
	free := poolByKind(t, placer.PoolUtilization(), PoolHousekeeping).FreeWholeCores

	res := placer.Allocate(Request{
		UUID:     uuid.NewV5(uuid.NamespaceOID, "greedy"),
		NumVCPUs: int(free) * 2,
		Mode:     ModeWholeCoreSMT,
		NUMA:     NUMABestEffort,
	})
	if res.Status != Success {
		t.Fatalf("the report promised %d whole cores but Allocate said %v: %s",
			free, res.Status, res.Message)
	}
	after := poolByKind(t, placer.PoolUtilization(), PoolHousekeeping)
	if after.FreeWholeCores != 0 {
		t.Errorf("all promised cores were taken, want 0 left, got %d",
			after.FreeWholeCores)
	}
}

// Ids the topology does not know about must not appear in the report: an
// isolcpus list naming a CPU this kernel does not expose would otherwise be
// echoed back to the controller as capacity.
func TestPoolUtilization_UnknownIsolatedCPUsIgnored(t *testing.T) {
	placer := newPlacer(smt2Topology(2), 0, lcpus(3, 99, 3))
	isolated := poolByKind(t, placer.PoolUtilization(), PoolIsolated)
	if !reflect.DeepEqual(isolated.CPUs, lcpus(3)) {
		t.Errorf("want only the known, de-duplicated CPU 3, got %v", isolated.CPUs)
	}
}
