// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"reflect"
	"slices"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// smt2Topology builds n physical cores with two SMT siblings each, numbered so
// that core i owns logical CPUs 2i and 2i+1.
func smt2Topology(n uint) *cputopology.Topology {
	var infos []cputopology.CPU
	for core := uint(0); core < n; core++ {
		for thread := uint(0); thread < 2; thread++ {
			infos = append(infos, cputopology.CPU{
				ID: cputopology.LCPU(core*2 + thread), Core: core,
			})
		}
	}
	return cputopology.Build(infos)
}

func lcpus(ids ...uint32) []cputopology.LCPU {
	out := make([]cputopology.LCPU, 0, len(ids))
	for _, id := range ids {
		out = append(out, cputopology.LCPU(id))
	}
	return out
}

// mustClaim makes id hold the given CPUs as a thread-granular assignment, as
// reseeding a running workload from its status does.
func mustClaim(t *testing.T, placer *Placer, id uuid.UUID, cpus ...uint32) {
	t.Helper()
	if err := placer.Claim(id, &Assignment{OrderedHostCPUs: lcpus(cpus...)}); err != nil {
		t.Fatalf("Claim(%s, %v): %v", id, cpus, err)
	}
}

func poolByKind(t *testing.T, pools []types.CPUPoolUtilization,
	want types.CPUPoolKind) types.CPUPoolUtilization {
	t.Helper()
	for _, pool := range pools {
		if pool.Kind == want {
			return pool
		}
	}
	t.Fatalf("no %s pool in %v", want, pools)
	return types.CPUPoolUtilization{}
}

func checkPool(t *testing.T, got, want types.CPUPoolUtilization) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s pool:\n got %+v\nwant %+v", want.Kind, got, want)
	}
}

// An 8-thread node with CPU 0 reserved for EVE, core3 (CPUs 6 and 7) isolated,
// app A holding one whole core and app B a single thread. Two of the four free
// threads (CPUs 1 and 5) sit on cores that are already partly taken, so the
// node can hand out exactly one whole core, core3, even though four threads are
// free -- which is the entire reason the whole-core counts are reported
// separately from the CPU lists.
func TestPools_WorkedExample(t *testing.T) {
	placer := testPlacer(t, smt2Topology(4), 1, lcpus(6, 7))
	mustClaim(t, placer, u("A"), 2, 3)
	mustClaim(t, placer, u("B"), 4)

	pools := placer.Pools()
	if len(pools) != 3 {
		t.Fatalf("want a report for every pool, got %d", len(pools))
	}

	checkPool(t, poolByKind(t, pools, types.CPUPoolKindHousekeeping), types.CPUPoolUtilization{
		Kind: types.CPUPoolKindHousekeeping,
		CPUs: []uint32{0, 1, 5},
		// cpu0 is reserved for EVE, so it is not free for a dedicated workload.
		FreeCPUs: []uint32{1, 5},
		// Only core0 lies wholly in the pool; core2 straddles it.
		TotalCores: 1,
		// core0 is not free whole: its sibling cpu0 belongs to EVE.
		FreeWholeCores: 0,
	})

	checkPool(t, poolByKind(t, pools, types.CPUPoolKindDedicated), types.CPUPoolUtilization{
		Kind: types.CPUPoolKindDedicated,
		CPUs: []uint32{2, 3, 4},
		// Only core1 lies wholly in the pool; core2's cpu5 does not.
		TotalCores: 1, FreeWholeCores: 0,
	})

	checkPool(t, poolByKind(t, pools, types.CPUPoolKindIsolated), types.CPUPoolUtilization{
		Kind: types.CPUPoolKindIsolated,
		CPUs: []uint32{6, 7},
		// The kernel-isolated core3 is a pool of its own, free for a workload
		// that requests isolation, and not counted in housekeeping.
		FreeCPUs:   []uint32{6, 7},
		TotalCores: 1, FreeWholeCores: 1,
	})
}

// The pools come in a fixed order, each tagged with its kind, an empty one
// with no CPUs at all, and none carries warnings: those are IsolationIssues'.
// A held core moves from housekeeping to dedicated and back when freed.
func TestPools_KindsAndCountsOnASmallNode(t *testing.T) {
	placer := testPlacer(t, twoCoresSMT2(), 1, nil) // cores {0,4} and {1,5}; CPU 0 reserved
	if r := allocate(t, placer, Request{UUID: u("opc"), NumVCPUs: 1, Mode: ModeOnePerCore}); r.Status != Success {
		t.Fatalf("core {1,5} is free, got %v (%s)", r.Status, r.Message)
	}
	pools := placer.Pools()
	var kinds []types.CPUPoolKind
	for _, pool := range pools {
		kinds = append(kinds, pool.Kind)
	}
	if want := []types.CPUPoolKind{types.CPUPoolKindHousekeeping, types.CPUPoolKindDedicated,
		types.CPUPoolKindIsolated}; !slices.Equal(kinds, want) {
		t.Fatalf("want pools %v, got %v", want, kinds)
	}
	checkPool(t, pools[0], types.CPUPoolUtilization{Kind: types.CPUPoolKindHousekeeping,
		CPUs: []uint32{0, 4}, FreeCPUs: []uint32{4}, TotalCores: 1})
	// The parked sibling 5 is held with the vCPU's CPU 1.
	checkPool(t, pools[1], types.CPUPoolUtilization{Kind: types.CPUPoolKindDedicated,
		CPUs: []uint32{1, 5}, TotalCores: 1})
	checkPool(t, pools[2], types.CPUPoolUtilization{Kind: types.CPUPoolKindIsolated})

	placer.Free(u("opc"))
	pools = placer.Pools()
	checkPool(t, pools[0], types.CPUPoolUtilization{Kind: types.CPUPoolKindHousekeeping,
		CPUs: []uint32{0, 1, 4, 5}, FreeCPUs: []uint32{1, 4, 5}, TotalCores: 2, FreeWholeCores: 1})
	checkPool(t, pools[1], types.CPUPoolUtilization{Kind: types.CPUPoolKindDedicated})
}

func TestLCPUsToUint32(t *testing.T) {
	if got := LCPUsToUint32(nil); got != nil {
		t.Errorf("want nil for no CPUs, got %v", got)
	}
	if got := LCPUsToUint32([]cputopology.LCPU{}); got != nil {
		t.Errorf("want nil for an empty list, got %v", got)
	}
	if got := LCPUsToUint32(lcpus(5, 0, 3)); !slices.Equal(got, []uint32{5, 0, 3}) {
		t.Errorf("want [5 0 3] in the given order, got %v", got)
	}
}

// The API defines the pools as disjoint and together covering the node, so a
// consumer can add them up. An ISOLATED workload's CPUs therefore count once, in
// the isolated pool, and not again as dedicated.
func TestPools_PoolsPartitionTheNode(t *testing.T) {
	placer := testPlacer(t, smt2Topology(4), 1, lcpus(6, 7))
	mustClaim(t, placer, u("soft"), 2, 3)
	mustClaim(t, placer, u("hard"), 6, 7)

	pools := placer.Pools()
	seen := map[uint32]types.CPUPoolKind{}
	total := 0
	for _, pool := range pools {
		total += len(pool.CPUs)
		for _, c := range pool.CPUs {
			if other, dup := seen[c]; dup {
				t.Errorf("cpu%d is in both the %s and the %s pool", c, other, pool.Kind)
			}
			seen[c] = pool.Kind
		}
	}
	if len(seen) != 8 || total != 8 {
		t.Errorf("the pools must cover all 8 CPUs exactly once, got %d CPUs and %d entries: %+v",
			len(seen), total, pools)
	}

	isolated := poolByKind(t, pools, types.CPUPoolKindIsolated)
	if !slices.Equal(isolated.CPUs, []uint32{6, 7}) || len(isolated.FreeCPUs) != 0 ||
		isolated.FreeWholeCores != 0 {
		t.Errorf("the isolated workload's core is allocated in the isolated pool, got %+v", isolated)
	}
	if dedicated := poolByKind(t, pools, types.CPUPoolKindDedicated); !slices.Equal(dedicated.CPUs, []uint32{2, 3}) {
		t.Errorf("dedicated holds only CPUs outside the isolated set, got %v", dedicated.CPUs)
	}
}

// A free CPU count cannot answer "does a whole-core workload fit?". With one
// thread taken on every core there are four free CPUs and no free core at
// all, so a consumer trusting the CPU count would promise capacity that does
// not exist.
func TestPools_FreeThreadsAreNotFreeCores(t *testing.T) {
	placer := testPlacer(t, smt2Topology(4), 0, nil)
	for i, cpu := range []uint32{0, 2, 4, 6} {
		mustClaim(t, placer, u(string(rune('a'+i))), cpu)
	}
	housekeeping := poolByKind(t, placer.Pools(), types.CPUPoolKindHousekeeping)
	if len(housekeeping.FreeCPUs) != 4 {
		t.Errorf("want 4 free CPUs, got %v", housekeeping.FreeCPUs)
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
func TestPools_IdleNode(t *testing.T) {
	pools := testPlacer(t, smt2Topology(4), 2, nil).Pools()

	housekeeping := poolByKind(t, pools, types.CPUPoolKindHousekeeping)
	if len(housekeeping.CPUs) != 8 || len(housekeeping.FreeCPUs) != 6 {
		t.Errorf("want 8 CPUs with 6 free, got %d/%d",
			len(housekeeping.CPUs), len(housekeeping.FreeCPUs))
	}
	// Reserving CPUs 0 and 1 withholds core0 whole: a core with a housekeeping
	// sibling is not a core a workload owns exclusively.
	if housekeeping.FreeWholeCores != 3 {
		t.Errorf("want 3 free whole cores, got %d", housekeeping.FreeWholeCores)
	}
	dedicated := poolByKind(t, pools, types.CPUPoolKindDedicated)
	if dedicated.CPUs != nil || dedicated.TotalCores != 0 {
		t.Errorf("nothing is dedicated, got %+v", dedicated)
	}
}

// Only the reported free whole-core count, never the free CPU count, should
// agree with what the allocator will actually hand out.
func TestPools_MatchesWhatProposeGrants(t *testing.T) {
	placer := testPlacer(t, smt2Topology(4), 1, nil)
	free := poolByKind(t, placer.Pools(), types.CPUPoolKindHousekeeping).FreeWholeCores

	res := allocate(t, placer, Request{
		UUID:     u("greedy"),
		NumVCPUs: int(free) * 2,
		Mode:     ModeWholeCoreSMT,
		NUMA:     NUMABestEffort,
	})
	if res.Status != Success {
		t.Fatalf("the report promised %d whole cores but Propose said %v: %s",
			free, res.Status, res.Message)
	}
	after := poolByKind(t, placer.Pools(), types.CPUPoolKindHousekeeping)
	if after.FreeWholeCores != 0 {
		t.Errorf("all promised cores were taken, want 0 left, got %d",
			after.FreeWholeCores)
	}
}

// Ids the topology does not know about must not appear in the report: an
// isolcpus list naming a CPU this kernel does not expose would otherwise be
// echoed back to the controller as capacity.
func TestPools_UnknownIsolatedCPUsIgnored(t *testing.T) {
	placer := testPlacer(t, smt2Topology(2), 0, lcpus(3, 99, 3))
	isolated := poolByKind(t, placer.Pools(), types.CPUPoolKindIsolated)
	if !slices.Equal(isolated.CPUs, []uint32{3}) {
		t.Errorf("want only the known, de-duplicated CPU 3, got %v", isolated.CPUs)
	}
	if got := placer.IsolatedCPUs(); !slices.Equal(got, lcpus(3)) {
		t.Errorf("want the placer to know only CPU 3 as isolated, got %v", got)
	}
}

// Neither thread of a core only partly isolated is reported free: placement
// gives such a core to no one, and the report must not promise it.
func TestPools_HalfIsolatedCoreIsNotFree(t *testing.T) {
	placer := testPlacer(t, smt2Topology(2), 0, lcpus(3))
	pools := placer.Pools()
	if free := poolByKind(t, pools, types.CPUPoolKindIsolated).FreeCPUs; len(free) != 0 {
		t.Errorf("isolated CPU 3 is half of a core, want no free isolated CPU, got %v", free)
	}
	if slices.Contains(poolByKind(t, pools, types.CPUPoolKindHousekeeping).FreeCPUs, 2) {
		t.Errorf("CPU 2 shares a core with isolated CPU 3 and must not be free")
	}
}
