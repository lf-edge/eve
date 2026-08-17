// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	uuid "github.com/satori/go.uuid"
)

func u(s string) uuid.UUID { return uuid.NewV5(uuid.NamespaceOID, s) }

func mustPlacer(t *testing.T, topo *cputopology.Topology, reserved uint32) *Placer {
	t.Helper()
	p, err := NewPlacer(topo, reserved)
	if err != nil {
		t.Fatalf("NewPlacer(reserved=%d): %v", reserved, err)
	}
	return p
}

// two physical cores, SMT2, single socket/NUMA/L3
func twoCoresSMT2() *cputopology.Topology {
	return cputopology.BuildTopology([]cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 4, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 5, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
	})
}

func TestPlacer_FreeAndDedicatedSet(t *testing.T) {
	p := mustPlacer(t, twoCoresSMT2(), 0)
	if len(p.DedicatedSet()) != 0 {
		t.Fatalf("fresh placer must have empty dedicated set, got %v", p.DedicatedSet())
	}
	p.Free(u("nobody")) // must not panic on unknown uuid
	if len(p.DedicatedSet()) != 0 {
		t.Fatalf("still empty after Free of unknown uuid")
	}
}

// 2 sockets x 4 physical cores x SMT2, distinct L3/NUMA per socket.
func twoSocketTopo() *cputopology.Topology {
	var infos []cputopology.CoreInfo
	lc := uint(0)
	for socket := uint(0); socket < 2; socket++ {
		for core := uint(0); core < 4; core++ {
			for thread := 0; thread < 2; thread++ {
				infos = append(infos, cputopology.CoreInfo{
					LCore: lc, Socket: socket, CoreID: core, NUMA: socket, L3ID: socket,
				})
				lc++
			}
		}
	}
	return cputopology.BuildTopology(infos)
}

// one physical core per NUMA node (forces NeedsRebalance for a 2-core request).
func twoNodesOneCoreEach() *cputopology.Topology {
	return cputopology.BuildTopology([]cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 2, Socket: 1, CoreID: 0, NUMA: 1, L3ID: 1},
		{LCore: 3, Socket: 1, CoreID: 0, NUMA: 1, L3ID: 1},
	})
}

func TestAllocate_WholeCoreSMT_NUMALocal(t *testing.T) {
	topo := twoSocketTopo()
	p := mustPlacer(t, topo, 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if a.Guest != (GuestTopology{Sockets: 1, Cores: 2, Threads: 2}) {
		t.Fatalf("guest topo want 1/2/2, got %+v", a.Guest)
	}
	if len(a.OrderedHostCPUs) != 4 {
		t.Fatalf("want 4 host cpus, got %d", len(a.OrderedHostCPUs))
	}
	n := topo.ByLCPU[a.OrderedHostCPUs[0]].NUMA
	for _, c := range a.OrderedHostCPUs {
		if topo.ByLCPU[c].NUMA != n {
			t.Fatalf("NUMA-local violated: %v", a.OrderedHostCPUs)
		}
	}
	// vCPU pair (0,1) must be SMT siblings (same physical core).
	if topo.ByLCPU[a.OrderedHostCPUs[0]].CoreID != topo.ByLCPU[a.OrderedHostCPUs[1]].CoreID {
		t.Fatalf("vcpu pair 0,1 not sibling-mapped: %v", a.OrderedHostCPUs)
	}
}

func TestAllocate_OddRejectedForSMT(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 3, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != InvalidRequest {
		t.Fatalf("odd vcpu in SMT mode must be InvalidRequest, got %v", r.Status)
	}
}

func TestAllocate_OnePerCore_ParksSiblings(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if r.Assignment.Guest.Threads != 1 {
		t.Fatalf("one-per-core guest threads must be 1, got %d", r.Assignment.Guest.Threads)
	}
	if len(r.Assignment.ParkedCPUs) != 2 {
		t.Fatalf("want 2 parked siblings, got %v", r.Assignment.ParkedCPUs)
	}
	if len(p.DedicatedSet()) != 4 {
		t.Fatalf("dedicated set must include parked siblings (want 4), got %d", len(p.DedicatedSet()))
	}
}

func TestAllocate_NoCrossVMCoreSharing(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("vm1 should succeed, got %v", r.Status)
	}
	r2 := p.Allocate(Request{UUID: u("vm2"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r2.Status != Success {
		t.Fatalf("vm2 should succeed (room remains), got %v (%s)", r2.Status, r2.Message)
	}
	seen := map[cputopology.LCPU]bool{}
	for _, c := range p.dedicated[u("vm1")] {
		seen[c] = true
	}
	for _, c := range p.dedicated[u("vm2")] {
		if seen[c] {
			t.Fatalf("cross-VM core sharing at lcpu %d", c)
		}
	}
}

func TestAllocate_NeedsRebalance(t *testing.T) {
	// Two NUMA nodes, one core each; a 2-core NUMA-local request can't fit in
	// one node even though total free (2) is enough.
	p := mustPlacer(t, twoNodesOneCoreEach(), 0)
	r := p.Allocate(Request{UUID: u("b"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != NeedsRebalance {
		t.Fatalf("want NeedsRebalance, got %v (%s)", r.Status, r.Message)
	}
	// The published retry condition quotes these numbers, so they are part of the
	// contract, not a debugging aid: a rebalance needs 2 cores and 2 are free,
	// just not in one node.
	if r.CoresNeeded != 2 || r.CoresFree != 2 {
		t.Errorf("want CoresNeeded=2 CoresFree=2, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

func TestAllocate_InsufficientTotal(t *testing.T) {
	p := mustPlacer(t, twoNodesOneCoreEach(), 0)
	// 6 vCPUs = 3 cores, but only 2 physical cores exist anywhere.
	r := p.Allocate(Request{UUID: u("x"), NumVCPUs: 6, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if r.CoresNeeded != 3 || r.CoresFree != 2 {
		t.Errorf("want CoresNeeded=3 CoresFree=2, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

func oneCoreTopo() *cputopology.Topology {
	return cputopology.BuildTopology([]cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
	})
}

func TestAllocate_ReservedCPUsExcluded(t *testing.T) {
	// twoCoresSMT2 cores: c0={0,4}, c1={1,5}. Reserve lcpu 0 -> core {0,4}
	// excluded wholesale, leaving 1 free core; a 2-core request must not fit.
	p := mustPlacer(t, twoCoresSMT2(), 1)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Insufficient {
		t.Fatalf("reserved core must be excluded -> Insufficient, got %v (%s)", r.Status, r.Message)
	}
	r := p.Allocate(Request{UUID: u("vm2"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("1-core request should fit on the non-reserved core, got %v (%s)", r.Status, r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if c == 0 || c == 4 {
			t.Fatalf("allocated a reserved core lcpu %d", c)
		}
	}
}

// fourCoresSMT2Interleaved is an 8-CPU / 4-core SMT2 host numbered the way
// Linux normally numbers one: lcpu 0..3 are the first thread of cores 0..3 and
// lcpu 4..7 the second. Reserving the lowest N CPUs therefore touches N
// *different* cores, which is what makes the whole-core reservation rule
// visible.
func fourCoresSMT2Interleaved() *cputopology.Topology {
	var infos []cputopology.CoreInfo
	for thread := uint(0); thread < 2; thread++ {
		for core := uint(0); core < 4; core++ {
			infos = append(infos, cputopology.CoreInfo{
				LCore: thread*4 + core, Socket: 0, CoreID: core, NUMA: 0, L3ID: 0,
			})
		}
	}
	return cputopology.BuildTopology(infos)
}

// Reserving CPUs for EVE withholds every physical core they sit on, whole. On
// an SMT host with the usual Linux numbering, cpusReserved=2 therefore costs
// two cores (four logical CPUs), not two logical CPUs -- so a 6-vCPU whole-core
// request does not fit on 8 CPUs. That is deliberate (a core EVE shares is not
// a core a workload owns exclusively) and the shortage must say so.
func TestAllocate_ReservedRangeWithholdsWholeCores(t *testing.T) {
	p := mustPlacer(t, fourCoresSMT2Interleaved(), 2) // lcpu 0 and 1 -> cores 0 and 1
	r := p.Allocate(Request{UUID: u("big"), NumVCPUs: 6, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("6 vCPUs must not fit behind 2 reserved CPUs, got %v (%s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "partly reserved") {
		t.Errorf("shortage must explain the reserved cores, got %q", r.Message)
	}
	// Exactly the two untouched cores remain usable.
	fits := p.Allocate(Request{UUID: u("fits"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if fits.Status != Success {
		t.Fatalf("the 2 fully free cores must still be allocatable, got %v (%s)",
			fits.Status, fits.Message)
	}
	for _, c := range fits.Assignment.OrderedHostCPUs {
		if pc := p.topo.ByLCPU[c]; pc.CoreID < 2 {
			t.Errorf("allocated core %d, which shares a thread with the reserved range", pc.CoreID)
		}
	}
}

// A shortage caused by hybrid single-thread cores must name that reason too, and
// must say it in terms of the thread count that was skipped: cores are dropped
// whenever their thread count differs from the request, which also covers
// 4-thread cores that do have siblings.
func TestAllocate_ShortageNamesCoresWithWrongThreadCount(t *testing.T) {
	p := mustPlacer(t, hybridTopo(), 0)
	r := p.Allocate(Request{UUID: u("smt"), NumVCPUs: 8, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if r.TopologyUnsupported {
		t.Error("SMT-capable cores exist, so this is a shortage, not an unsupported request")
	}
	if !strings.Contains(r.Message, "do not have exactly 2 hardware threads") {
		t.Errorf("shortage must explain the skipped cores, got %q", r.Message)
	}
	// 8 vCPUs = 4 cores; only the two SMT P-cores can serve them.
	if r.CoresNeeded != 4 || r.CoresFree != 2 {
		t.Errorf("want CoresNeeded=4 CoresFree=2, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

// Reserving every CPU for EVE is a misconfigured eve_max_vcpus, not a runtime
// state: it must fail at construction rather than turn every later placement
// into an unexplained shortage.
func TestNewPlacer_RejectsOverReservation(t *testing.T) {
	topo := fourCoresSMT2Interleaved() // 8 logical CPUs
	for _, reserved := range []uint32{8, 9, 100} {
		if _, err := NewPlacer(topo, reserved); err == nil {
			t.Errorf("reserving %d of 8 CPUs must be rejected", reserved)
		}
	}
	if _, err := NewPlacer(topo, 7); err != nil {
		t.Errorf("reserving 7 of 8 CPUs still leaves one, must be accepted: %v", err)
	}
	if _, err := NewPlacer(nil, 0); err == nil {
		t.Error("a nil topology must be rejected")
	}
}

func TestAllocate_DoubleAllocateRejected(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("first allocate should succeed, got %v", r.Status)
	}
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != InvalidRequest {
		t.Fatalf("re-allocating same UUID must be InvalidRequest, got %v (%s)", r.Status, r.Message)
	}
}

func TestAllocate_AllowCrossSpansNodes(t *testing.T) {
	p := mustPlacer(t, twoNodesOneCoreEach(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Success {
		t.Fatalf("allow-cross should span both nodes and succeed, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.NUMANodes) != 2 {
		t.Fatalf("want assignment spanning 2 NUMA nodes, got %v", r.Assignment.NUMANodes)
	}
	if len(r.Assignment.OrderedHostCPUs) != 4 {
		t.Fatalf("want 4 host cpus, got %d", len(r.Assignment.OrderedHostCPUs))
	}
}

func TestAllocate_ParkedSiblingBlocksReuse(t *testing.T) {
	p := mustPlacer(t, oneCoreTopo(), 0)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("first one-per-core should succeed, got %v", r.Status)
	}
	r := p.Allocate(Request{UUID: u("vm2"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Insufficient {
		t.Fatalf("parked sibling must block core reuse -> Insufficient, got %v (%s)", r.Status, r.Message)
	}
}

func TestAllocateShared_Basic(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	got, err := p.AllocateShared(u("legacy"), 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("want 3 cpus, got %v err %v", got, err)
	}
	if len(p.DedicatedSet()) != 3 {
		t.Fatalf("shared alloc must be in dedicated set")
	}
}

func TestAllocateShared_SkipsReserved(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 2) // reserve lcpus 0,1
	got, _ := p.AllocateShared(u("legacy"), 1)
	if got[0] < 2 {
		t.Fatalf("must skip reserved cpus 0,1, got %v", got)
	}
}

func TestMixed_NoOverlap_TopologyThenShared(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatal(r.Message)
	}
	// collect vm1's cpus
	vm1 := map[uint32]bool{}
	for _, c := range p.dedicated[u("vm1")] {
		vm1[uint32(c)] = true
	}
	got, err := p.AllocateShared(u("legacy"), 8)
	if err != nil {
		t.Fatalf("legacy alloc should fit remaining cores: %v", err)
	}
	for _, c := range got {
		if vm1[uint32(c)] {
			t.Fatalf("shared alloc reused topology-dedicated cpu %d", c)
		}
	}
}

func TestMixed_NoOverlap_SharedThenTopology(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	shared, _ := p.AllocateShared(u("legacy"), 2)
	sharedSet := map[uint32]bool{}
	for _, c := range shared {
		sharedSet[uint32(c)] = true
	}
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatal(r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if sharedSet[uint32(c)] {
			t.Fatalf("topology alloc reused shared cpu %d", c)
		}
	}
}

// hybridTopo mirrors an Intel hybrid part: two SMT2 P-cores (lcpu 0/1 on core
// 0, 2/3 on core 1) plus four single-thread E-cores (lcpu 4..7 on cores 2..5),
// single socket/NUMA/L3.
func hybridTopo() *cputopology.Topology {
	infos := []cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 2, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 3, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
	}
	for i := 0; i < 4; i++ {
		infos = append(infos, cputopology.CoreInfo{
			LCore: uint(4 + i), Socket: 0, CoreID: uint(2 + i), NUMA: 0, L3ID: 0,
		})
	}
	return cputopology.BuildTopology(infos)
}

// whole-core-smt must place a vCPU on each SMT sibling of ONE physical core and
// never satisfy the request with a single-thread (E) core, which cannot present
// threads=2. Regression for the hybrid-CPU count mismatch (ordered < vCPUs).
func TestAllocate_WholeCoreSMT_HybridSkipsSingleThread(t *testing.T) {
	p := mustPlacer(t, hybridTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if len(a.OrderedHostCPUs) != 2 {
		t.Fatalf("whole-core-smt must map one host CPU per vCPU (2), got %d: %v",
			len(a.OrderedHostCPUs), a.OrderedHostCPUs)
	}
	if a.Guest.Threads != 2 {
		t.Fatalf("guest threads must be 2, got %d", a.Guest.Threads)
	}
	c0 := p.topo.ByLCPU[a.OrderedHostCPUs[0]]
	c1 := p.topo.ByLCPU[a.OrderedHostCPUs[1]]
	if c0.Socket != c1.Socket || c0.CoreID != c1.CoreID {
		t.Fatalf("vCPUs not on one physical core: %v", a.OrderedHostCPUs)
	}
	if len(c0.Siblings) != 2 {
		t.Fatalf("whole-core-smt used a non-SMT core (siblings=%v)", c0.Siblings)
	}
}

// With both SMT cores unavailable and only single-thread E-cores free,
// whole-core-smt must fail cleanly with Insufficient rather than emit an
// assignment with fewer host CPUs than vCPUs.
func TestAllocate_WholeCoreSMT_OnlyECoresFree(t *testing.T) {
	p := mustPlacer(t, hybridTopo(), 4) // reserve lcpu 0-3 -> both P-cores excluded
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Insufficient {
		t.Fatalf("no full-SMT core free must be Insufficient, got %v (%s)", r.Status, r.Message)
	}
}

// one-per-core may use single-thread E-cores (one vCPU per physical core, no
// sibling to park).
func TestAllocate_OnePerCore_UsesSingleThreadCores(t *testing.T) {
	p := mustPlacer(t, hybridTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if len(a.OrderedHostCPUs) != 4 {
		t.Fatalf("one-per-core must map one host CPU per vCPU (4), got %v", a.OrderedHostCPUs)
	}
	usedECore := false
	for _, c := range a.OrderedHostCPUs {
		if len(p.topo.ByLCPU[c].Siblings) == 1 {
			usedECore = true
		}
	}
	if !usedECore {
		t.Fatalf("one-per-core should be able to use single-thread cores: %v", a.OrderedHostCPUs)
	}
}

// A whole-core-smt VM and a one-per-core VM must coexist on a hybrid host with
// no physical core shared between them.
func TestAllocate_Hybrid_Coexistence(t *testing.T) {
	p := mustPlacer(t, hybridTopo(), 0)
	if r := p.Allocate(Request{UUID: u("smt"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("whole-core-smt vm should succeed, got %v (%s)", r.Status, r.Message)
	}
	if r := p.Allocate(Request{UUID: u("opc"), NumVCPUs: 4, Mode: ModeOnePerCore, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("one-per-core vm should coexist, got %v (%s)", r.Status, r.Message)
	}
	seen := map[cputopology.LCPU]bool{}
	for _, c := range p.dedicated[u("smt")] {
		seen[c] = true
	}
	for _, c := range p.dedicated[u("opc")] {
		if seen[c] {
			t.Fatalf("core sharing between VMs at lcpu %d", c)
		}
	}
}

// best-effort stays within one NUMA node when the request fits.
func TestAllocate_BestEffort_FitsSingleNode(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.NUMANodes) != 1 {
		t.Fatalf("best-effort should stay on one node when it fits, got %v", r.Assignment.NUMANodes)
	}
}

// best-effort falls back to spanning nodes rather than failing when no single
// node fits (contrast NUMALocal, which returns NeedsRebalance here).
func TestAllocate_BestEffort_FallsBackToSpanning(t *testing.T) {
	p := mustPlacer(t, twoNodesOneCoreEach(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("best-effort must fall back to spanning, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.NUMANodes) != 2 {
		t.Fatalf("expected spanning 2 nodes, got %v", r.Assignment.NUMANodes)
	}
}

// Reserve seeds a running VM's cores so a fresh Placer (post-restart) does not
// hand them to another VM; Free returns them to the pool.
func TestReserve_BlocksAndFrees(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0) // 16 lcpus
	if err := p.Reserve(u("running"), []uint32{0, 1, 2, 3}); err != nil {
		t.Fatalf("Reserve of a running VM's cores: %v", err)
	}
	if len(p.FreeCPUs()) != 16-4 {
		t.Fatalf("reserved cpus must be excluded from FreeCPUs, got %d", len(p.FreeCPUs()))
	}
	r := p.Allocate(Request{UUID: u("new"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("new VM should allocate around reserved cores, got %v (%s)", r.Status, r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if c <= 3 {
			t.Fatalf("new VM got a reserved core %d", c)
		}
	}
	if err := p.Reserve(u("running"), []uint32{0, 1, 2, 3}); err != nil {
		t.Errorf("replaying the identical reservation must be a no-op, got %v", err)
	}
	p.Free(u("running"))
	if len(p.FreeCPUs()) != 16-len(r.Assignment.OrderedHostCPUs) {
		t.Fatalf("after Free, reserved cores must return to the free pool")
	}
}

// Reserve reseeds the placer from persisted DomainStatus, which is precisely
// where a stale or conflicting claim can appear. Recording one verbatim would let
// two workloads own a CPU, making HolderOf name an arbitrary owner and the
// allocator hand the CPU out twice, so every malformed claim must be refused --
// and refused without changing anything.
func TestReserve_RejectsClaimsItCannotHonour(t *testing.T) {
	running, other := u("running"), u("other")

	newSeeded := func(t *testing.T) *Placer {
		t.Helper()
		p := mustPlacer(t, twoSocketTopo(), 0) // lcpus 0..15
		if err := p.Reserve(running, []uint32{0, 1}); err != nil {
			t.Fatalf("seed Reserve: %v", err)
		}
		return p
	}

	tests := []struct {
		name string
		id   uuid.UUID
		cpus []uint32
	}{
		{"an empty CPU set claims nothing", other, nil},
		{"a logical CPU the host does not have", other, []uint32{99}},
		{"a CPU another workload already holds", other, []uint32{1}},
		{"a second, different claim by the same id", running, []uint32{2, 3}},
		{"a claim that only partly overlaps its own", running, []uint32{0, 1, 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newSeeded(t)
			before := p.DedicatedSet()
			if err := p.Reserve(tc.id, tc.cpus); err == nil {
				t.Fatalf("Reserve(%s, %v) must be rejected", tc.id, tc.cpus)
			}
			if !equalLCPUs(before, p.DedicatedSet()) {
				t.Errorf("a rejected Reserve must change nothing: %v -> %v",
					before, p.DedicatedSet())
			}
		})
	}

	// The same set in a different order is the same reservation, so replaying a
	// status must not be treated as a conflict.
	p := newSeeded(t)
	if err := p.Reserve(running, []uint32{1, 0}); err != nil {
		t.Errorf("re-reserving the same set in another order must be a no-op, got %v", err)
	}
}

// The zero value of Status must not be Success. A Result that was never filled
// in -- dropped in a map lookup miss, defaulted in a struct, decoded from an
// empty message -- would otherwise read as an approved placement, and a caller
// would pin a VM to an empty CPU set on the allocator's supposed authority.
func TestStatus_ZeroValueIsNotSuccess(t *testing.T) {
	var missing Result
	if missing.Status == Success {
		t.Fatal("the zero Status must not be Success")
	}
	if missing.Status != StatusUnspecified {
		t.Fatalf("the zero Status must be StatusUnspecified, got %v", missing.Status)
	}
	if got := StatusUnspecified.String(); got != "unspecified" {
		t.Errorf("StatusUnspecified.String() = %q", got)
	}
	// A map miss is the way this reaches a caller in practice.
	if plan := map[uuid.UUID]Result{}; plan[u("never-planned")].Status == Success {
		t.Error("a workload absent from a plan must not read as placed")
	}
}

// noSMTTopo is a node whose cores have a single hardware thread each: SMT
// disabled in firmware, or a part that never had it (most ARM64).
func noSMTTopo() *cputopology.Topology {
	var infos []cputopology.CoreInfo
	for core := uint(0); core < 4; core++ {
		infos = append(infos, cputopology.CoreInfo{LCore: core, CoreID: core})
	}
	return cputopology.BuildTopology(infos)
}

// A whole-core-SMT request on a node with no SMT-capable core at all is
// unsatisfiable, not short of capacity. Reported as a shortage it produced advice
// -- stop another pinned workload, get a node with more cores -- of which every
// clause is false here, sending the operator after capacity that could never
// help. This is the likeliest failure of the default pinning policy.
func TestAllocate_WholeCoreSMT_NoSMTAnywhereIsUnsatisfiable(t *testing.T) {
	p := mustPlacer(t, noSMTTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != InvalidRequest {
		t.Fatalf("want InvalidRequest, got %v (%s)", r.Status, r.Message)
	}
	if !r.TopologyUnsupported {
		t.Error("the node cannot satisfy this in any arrangement; TopologyUnsupported must be set")
	}
	if r.CoresNeeded != 0 || r.CoresFree != 0 {
		t.Errorf("an unsatisfiable request is not a shortage, so no core counts: got %d/%d",
			r.CoresNeeded, r.CoresFree)
	}
	for _, want := range []string{"SMT sibling", "threads=2"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("message must say what is wrong (%q), got %q", want, r.Message)
		}
	}
	// Nothing was reserved, and the node is still usable for one-per-core.
	if len(p.DedicatedSet()) != 0 {
		t.Errorf("a refused request must reserve nothing, got %v", p.DedicatedSet())
	}
	if opc := p.Allocate(Request{UUID: u("opc"), NumVCPUs: 2, Mode: ModeOnePerCore,
		NUMA: NUMABestEffort}); opc.Status != Success {
		t.Errorf("one-per-core must still work on a non-SMT node, got %v (%s)",
			opc.Status, opc.Message)
	}
}

// The contrast case: SMT-capable cores do exist but are all taken. That IS a
// shortage -- freeing CPUs would help -- so it must stay Insufficient with the
// core counts the retry condition quotes, and must not claim the topology cannot
// do it.
func TestAllocate_WholeCoreSMT_BusySMTCoresAreAShortage(t *testing.T) {
	p := mustPlacer(t, twoCoresSMT2(), 0) // cores {0,4} and {1,5}
	if r := p.Allocate(Request{UUID: u("holder"), NumVCPUs: 4, Mode: ModeWholeCoreSMT,
		NUMA: NUMABestEffort}); r.Status != Success {
		t.Fatalf("holder must take both cores, got %v (%s)", r.Status, r.Message)
	}
	r := p.Allocate(Request{UUID: u("late"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if r.TopologyUnsupported {
		t.Error("the cores exist and are merely busy; freeing them would help")
	}
	if r.CoresNeeded != 1 || r.CoresFree != 0 {
		t.Errorf("want CoresNeeded=1 CoresFree=0, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

// The SMT sibling parked by a one-per-core request is held, not idle capacity:
// handing it to anyone else gives back exactly the interference the mode exists
// to remove. Every view of the node must agree it is taken.
func TestAllocate_OnePerCore_ParkedSiblingIsWithheldEverywhere(t *testing.T) {
	p := mustPlacer(t, twoCoresSMT2(), 0) // cores {0,4} and {1,5}
	r := p.Allocate(Request{UUID: u("opc"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.ParkedCPUs) != 1 {
		t.Fatalf("want exactly one parked sibling, got %v", r.Assignment.ParkedCPUs)
	}
	parked := r.Assignment.ParkedCPUs[0]

	for _, c := range p.FreeCPUs() {
		if c == parked {
			t.Errorf("parked sibling %d must not be free, got %v", parked, p.FreeCPUs())
		}
	}
	shared, err := p.AllocateShared(u("legacy"), 2)
	if err != nil {
		t.Fatalf("the remaining whole core must still serve a shared request: %v", err)
	}
	for _, c := range shared {
		if c == parked {
			t.Errorf("shared allocation took the parked sibling %d: %v", parked, shared)
		}
	}
	dedicated := poolByKind(t, p.PoolUtilization(nil), PoolDedicated)
	found := false
	for _, c := range dedicated.CPUs {
		if c == parked {
			found = true
		}
	}
	if !found {
		t.Errorf("parked sibling %d must be reported in the dedicated pool, got %v",
			parked, dedicated.CPUs)
	}
	if dedicated.FreeThreads != 0 {
		t.Errorf("nothing in the dedicated pool is free, got %d free threads",
			dedicated.FreeThreads)
	}
}

// The guest -smp topology and the host CPU list are two views of one decision and
// nothing downstream cross-checks them: an inconsistency reaches the operator as
// a domain that will not start. validate is the only place that can catch it, so
// each way of getting it wrong must be caught.
func TestAssignment_ValidateRejectsInconsistentPlacements(t *testing.T) {
	topo := twoNodesOneCoreEach() // core {0,1} in node 0, core {2,3} in node 1

	good := &Assignment{
		OrderedHostCPUs: lcpus(0, 1),
		Guest:           GuestTopology{Sockets: 1, Cores: 1, Threads: 2},
		NUMANodes:       []uint{0},
	}
	if err := good.validate(topo); err != nil {
		t.Fatalf("a consistent assignment must validate: %v", err)
	}

	tests := []struct {
		name string
		a    *Assignment
	}{
		{"vCPU count disagrees with the guest topology", &Assignment{
			OrderedHostCPUs: lcpus(0, 1, 2),
			Guest:           GuestTopology{Sockets: 1, Cores: 1, Threads: 2},
			NUMANodes:       []uint{0, 1},
		}},
		{"one host CPU serving two vCPUs", &Assignment{
			OrderedHostCPUs: lcpus(0, 0),
			Guest:           GuestTopology{Sockets: 1, Cores: 1, Threads: 2},
			NUMANodes:       []uint{0},
		}},
		{"a CPU both parked and running a vCPU", &Assignment{
			OrderedHostCPUs: lcpus(0, 1),
			Guest:           GuestTopology{Sockets: 1, Cores: 1, Threads: 2},
			ParkedCPUs:      lcpus(1),
			NUMANodes:       []uint{0},
		}},
		{"a host CPU the topology does not have", &Assignment{
			OrderedHostCPUs: lcpus(0, 99),
			Guest:           GuestTopology{Sockets: 1, Cores: 1, Threads: 2},
			NUMANodes:       []uint{0},
		}},
		{"NUMANodes missing a node the CPUs are in", &Assignment{
			OrderedHostCPUs: lcpus(0, 2),
			Guest:           GuestTopology{Sockets: 1, Cores: 2, Threads: 1},
			NUMANodes:       []uint{0},
		}},
		{"NUMANodes naming a node no CPU is in", &Assignment{
			OrderedHostCPUs: lcpus(0, 1),
			Guest:           GuestTopology{Sockets: 1, Cores: 1, Threads: 2},
			NUMANodes:       []uint{1},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.a.validate(topo); err == nil {
				t.Errorf("must be rejected: %+v", tc.a)
			}
		})
	}
}

// Every assignment Allocate returns must pass its own consistency check, across
// the modes and NUMA policies that build one differently.
func TestAllocate_SuccessfulAssignmentsAreConsistent(t *testing.T) {
	for _, tc := range []struct {
		name string
		topo *cputopology.Topology
		r    Request
	}{
		{"whole-core-smt in one node", twoSocketTopo(),
			Request{UUID: u("a"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}},
		{"whole-core-smt spanning nodes", twoNodesOneCoreEach(),
			Request{UUID: u("b"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross}},
		{"one-per-core parking siblings", twoSocketTopo(),
			Request{UUID: u("c"), NumVCPUs: 3, Mode: ModeOnePerCore, NUMA: NUMABestEffort}},
		{"one-per-core on single-thread cores", hybridTopo(),
			Request{UUID: u("d"), NumVCPUs: 5, Mode: ModeOnePerCore, NUMA: NUMABestEffort}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustPlacer(t, tc.topo, 0)
			res := p.Allocate(tc.r)
			if res.Status != Success {
				t.Fatalf("want Success, got %v (%s)", res.Status, res.Message)
			}
			if err := res.Assignment.validate(p.topo); err != nil {
				t.Errorf("Allocate returned an inconsistent assignment: %v", err)
			}
		})
	}
}

func TestFreeCPUs_ExcludesBoth(t *testing.T) {
	p := mustPlacer(t, twoSocketTopo(), 0)                                                        // 16 lcpus total
	_ = p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}) // 4 lcpus
	_, _ = p.AllocateShared(u("legacy"), 2)                                                       // 2 lcpus
	free := p.FreeCPUs()
	if len(free) != 16-4-2 {
		t.Fatalf("FreeCPUs should exclude both allocations: got %d", len(free))
	}
	p.Free(u("vm1"))
	p.Free(u("legacy"))
	if len(p.FreeCPUs()) != 16 {
		t.Fatalf("after Free all cpus should be free")
	}
}
