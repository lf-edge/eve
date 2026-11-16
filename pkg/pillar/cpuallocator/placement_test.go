// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func u(s string) uuid.UUID { return uuid.NewV5(uuid.NamespaceOID, s) }

// testPlacer builds a placer through NewPlacer over a node that reserves CPUs
// 0..reservedN-1 for EVE and whose kernel isolates the given logical CPUs.
func testPlacer(t *testing.T, topo *cputopology.Topology, reservedN int,
	isolated []cputopology.LCPU) *Placer {
	t.Helper()
	var reserved []cputopology.LCPU
	for c := 0; c < reservedN; c++ {
		reserved = append(reserved, cputopology.LCPU(c))
	}
	p, err := NewPlacer(topo, reserved, isolated)
	if err != nil {
		t.Fatalf("NewPlacer(reserved=%v, isolated=%v): %v", reserved, isolated, err)
	}
	return p
}

// allocate places a request and holds what it was given, as domainmgr does
// when a workload starts: Propose, then Claim on Success.
func allocate(t *testing.T, p *Placer, r Request) Result {
	t.Helper()
	res := p.Propose(r)
	if res.Status == Success {
		if err := p.Claim(r.UUID, res.Assignment); err != nil {
			t.Fatalf("Claim(%s) of its own proposal: %v", r.UUID, err)
		}
	}
	return res
}

// allocShared places a thread-granular request the way the plan and domainmgr
// do, returning the CPUs or the shortage as an error.
func allocShared(t *testing.T, p *Placer, id string, n int) ([]cputopology.LCPU, error) {
	t.Helper()
	r := allocate(t, p, Request{UUID: u(id), NumVCPUs: n, Mode: ModeShared})
	if r.Status != Success {
		return nil, fmt.Errorf("%v: %s", r.Status, r.Message)
	}
	return r.Assignment.OrderedHostCPUs, nil
}

// freeCPUs is every CPU no workload holds.
func freeCPUs(p *Placer) []cputopology.LCPU {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.freeCPUs()
}

// dedicatedSet is every CPU some workload holds, ascending.
func dedicatedSet(p *Placer) []cputopology.LCPU {
	return slices.Sorted(maps.Keys(p.Holders()))
}

// numaNodes is the NUMA nodes an assignment's vCPUs run on, ascending.
func numaNodes(topo *cputopology.Topology, a *Assignment) []uint {
	var nodes []uint
	for _, c := range a.OrderedHostCPUs {
		nodes = append(nodes, topo.CoreOf(c).NUMA)
	}
	slices.Sort(nodes)
	return slices.Compact(nodes)
}

// two physical cores, SMT2, single socket/NUMA/L3
func twoCoresSMT2() *cputopology.Topology {
	return cputopology.Build([]cputopology.CPU{
		{ID: 0, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 4, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 1, Socket: 0, Core: 1, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 5, Socket: 0, Core: 1, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
	})
}

func TestPlacer_FreeOfAnUnknownWorkloadIsSafe(t *testing.T) {
	p := testPlacer(t, twoCoresSMT2(), 0, nil)
	if len(dedicatedSet(p)) != 0 {
		t.Fatalf("fresh placer must have empty dedicated set, got %v", dedicatedSet(p))
	}
	p.Free(u("nobody")) // must not panic on unknown uuid
	if len(dedicatedSet(p)) != 0 {
		t.Fatalf("still empty after Free of unknown uuid")
	}
}

// 2 sockets x 4 physical cores x SMT2, distinct L3/NUMA per socket.
func twoSocketTopo() *cputopology.Topology {
	var infos []cputopology.CPU
	lc := uint(0)
	for socket := uint(0); socket < 2; socket++ {
		for core := uint(0); core < 4; core++ {
			for thread := 0; thread < 2; thread++ {
				infos = append(infos, cputopology.CPU{
					ID: cputopology.LCPU(lc), Socket: socket, Core: core, NUMA: socket, L3: cputopology.CacheID{ID: uint32(socket), Known: true},
				})
				lc++
			}
		}
	}
	return cputopology.Build(infos)
}

// one physical core per NUMA node (forces NeedsRebalance for a 2-core request).
func twoNodesOneCoreEach() *cputopology.Topology {
	return cputopology.Build([]cputopology.CPU{
		{ID: 0, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 1, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 2, Socket: 1, Core: 0, NUMA: 1, L3: cputopology.CacheID{ID: 1, Known: true}},
		{ID: 3, Socket: 1, Core: 0, NUMA: 1, L3: cputopology.CacheID{ID: 1, Known: true}},
	})
}

func TestAllocate_WholeCoreSMT_NUMALocal(t *testing.T) {
	topo := twoSocketTopo()
	p := testPlacer(t, topo, 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if a.Guest != (types.CPUTopology{Sockets: 1, Cores: 2, Threads: 2}) {
		t.Fatalf("guest topo want 1/2/2, got %+v", a.Guest)
	}
	if len(a.OrderedHostCPUs) != 4 {
		t.Fatalf("want 4 host cpus, got %d", len(a.OrderedHostCPUs))
	}
	n := topo.CoreOf(a.OrderedHostCPUs[0]).NUMA
	for _, c := range a.OrderedHostCPUs {
		if topo.CoreOf(c).NUMA != n {
			t.Fatalf("NUMA-local violated: %v", a.OrderedHostCPUs)
		}
	}
	// vCPU pair (0,1) must be SMT siblings (same physical core).
	if topo.CoreOf(a.OrderedHostCPUs[0]).ID != topo.CoreOf(a.OrderedHostCPUs[1]).ID {
		t.Fatalf("vcpu pair 0,1 not sibling-mapped: %v", a.OrderedHostCPUs)
	}
}

func TestAllocate_OddRejectedForSMT(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 3, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != InvalidRequest {
		t.Fatalf("odd vcpu in SMT mode must be InvalidRequest, got %v", r.Status)
	}
}

// A request no node could serve as sent is InvalidRequest, whatever is free.
func TestPropose_InvalidRequests(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	for _, r := range []Request{
		{UUID: u("none"), NumVCPUs: 0, Mode: ModeOnePerCore},
		{UUID: u("negative"), NumVCPUs: -1, Mode: ModeShared},
		{UUID: u("mode"), NumVCPUs: 2, Mode: PinMode(42)},
		{UUID: u("isolated-shared"), NumVCPUs: 1, Mode: ModeShared, RequireIsolated: true},
	} {
		if got := p.Propose(r); got.Status != InvalidRequest || got.Assignment != nil {
			t.Errorf("%d vCPUs, mode %v: want InvalidRequest, got %v (%s)",
				r.NumVCPUs, r.Mode, got.Status, got.Message)
		}
	}
}

func TestAllocate_OnePerCore_ParksSiblings(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if r.Assignment.Guest.Threads != 1 {
		t.Fatalf("one-per-core guest threads must be 1, got %d", r.Assignment.Guest.Threads)
	}
	if len(r.Assignment.ParkedCPUs) != 2 {
		t.Fatalf("want 2 parked siblings, got %v", r.Assignment.ParkedCPUs)
	}
	if len(dedicatedSet(p)) != 4 {
		t.Fatalf("dedicated set must include parked siblings (want 4), got %d", len(dedicatedSet(p)))
	}
}

func TestAllocate_NoCrossVMCoreSharing(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	if r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("vm1 should succeed, got %v", r.Status)
	}
	r2 := allocate(t, p, Request{UUID: u("vm2"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
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
	p := testPlacer(t, twoNodesOneCoreEach(), 0, nil)
	r := allocate(t, p, Request{UUID: u("b"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
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
	p := testPlacer(t, twoNodesOneCoreEach(), 0, nil)
	// 6 vCPUs = 3 cores, but only 2 physical cores exist anywhere.
	r := allocate(t, p, Request{UUID: u("x"), NumVCPUs: 6, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if r.CoresNeeded != 3 || r.CoresFree != 2 {
		t.Errorf("want CoresNeeded=3 CoresFree=2, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

func oneCoreTopo() *cputopology.Topology {
	return cputopology.Build([]cputopology.CPU{
		{ID: 0, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 1, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
	})
}

func TestAllocate_ReservedCPUsExcluded(t *testing.T) {
	// twoCoresSMT2 cores: c0={0,4}, c1={1,5}. Reserve lcpu 0 -> core {0,4}
	// excluded wholesale, leaving 1 free core; a 2-core request must not fit.
	p := testPlacer(t, twoCoresSMT2(), 1, nil)
	if r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Insufficient {
		t.Fatalf("reserved core must be excluded -> Insufficient, got %v (%s)", r.Status, r.Message)
	}
	r := allocate(t, p, Request{UUID: u("vm2"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
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
	var infos []cputopology.CPU
	for thread := uint(0); thread < 2; thread++ {
		for core := uint(0); core < 4; core++ {
			infos = append(infos, cputopology.CPU{
				ID: cputopology.LCPU(thread*4 + core), Socket: 0, Core: core, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true},
			})
		}
	}
	return cputopology.Build(infos)
}

// Reserving CPUs for EVE withholds every physical core they sit on, whole. On
// an SMT host with the usual Linux numbering, reserving CPUs 0 and 1 therefore
// costs two cores (four logical CPUs), not two logical CPUs -- so a 6-vCPU
// whole-core request does not fit on 8 CPUs. That is deliberate (a core EVE
// shares is not a core a workload owns exclusively) and the shortage must say so.
func TestAllocate_ReservedRangeWithholdsWholeCores(t *testing.T) {
	p := testPlacer(t, fourCoresSMT2Interleaved(), 2, nil) // lcpu 0 and 1 -> cores 0 and 1
	r := allocate(t, p, Request{UUID: u("big"), NumVCPUs: 6, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("6 vCPUs must not fit behind 2 reserved CPUs, got %v (%s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "partly reserved") {
		t.Errorf("shortage must explain the reserved cores, got %q", r.Message)
	}
	// Exactly the two untouched cores remain usable.
	fits := allocate(t, p, Request{UUID: u("fits"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if fits.Status != Success {
		t.Fatalf("the 2 fully free cores must still be allocatable, got %v (%s)",
			fits.Status, fits.Message)
	}
	for _, c := range fits.Assignment.OrderedHostCPUs {
		if pc := p.topo.CoreOf(c); pc.ID < 2 {
			t.Errorf("allocated core %d, which shares a thread with the reserved range", pc.ID)
		}
	}
}

// The reserved CPUs are the set EVE's cgroup runs on, wherever they sit, not
// the lowest N: a reserved thread withholds its core at any position, and the
// low cores outside the set are handed out.
func TestNewPlacer_ReservedIsASet(t *testing.T) {
	p, err := NewPlacer(fourCoresSMT2Interleaved(), lcpus(7, 99), lcpus(42))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.IsolatedCPUs(); len(got) != 0 {
		t.Errorf("an isolated CPU the topology lacks must be ignored, got %v", got)
	}
	r := allocate(t, p, Request{UUID: u("big"), NumVCPUs: 6, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Success {
		t.Fatalf("cores 0-2 are free, got %v (%s)", r.Status, r.Message)
	}
	if want := lcpus(0, 4, 1, 5, 2, 6); !slices.Equal(r.Assignment.OrderedHostCPUs, want) {
		t.Errorf("want cores 0-2 %v, off core 3 whose CPU 7 is reserved, got %v",
			want, r.Assignment.OrderedHostCPUs)
	}
	more := p.Propose(Request{UUID: u("more"), NumVCPUs: 1, Mode: ModeOnePerCore})
	if more.Status != Insufficient || !strings.Contains(more.Message, "1 cores are partly reserved for EVE") {
		t.Errorf("want a shortage naming core 3 as reserved, got %v (%s)", more.Status, more.Message)
	}
}

// A request for isolation on a full isolated pool is short because other
// workloads hold the isolated cores, and the refusal has to say so. EVE's core
// could never serve such a request, so it is no reason and must not be named.
func TestAllocate_IsolatedShortageNamesHeldCores(t *testing.T) {
	// Cores 2 and 3 (lcpus 2,6 and 3,7) isolated; lcpu 0 reserved for EVE.
	p := testPlacer(t, fourCoresSMT2Interleaved(), 1, lcpus(2, 3, 6, 7))
	iso := func(id string, n int) Result {
		return allocate(t, p, Request{UUID: u(id), NumVCPUs: n, Mode: ModeWholeCoreSMT,
			NUMA: NUMAAllowCross, RequireIsolated: true})
	}
	if r := iso("first", 4); r.Status != Success {
		t.Fatalf("both isolated cores are free, got %v (%s)", r.Status, r.Message)
	}
	r := iso("second", 2)
	if r.Status != Insufficient {
		t.Fatalf("the isolated pool is full, want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	want := "need 1 free kernel-isolated cores, have 0 (2 are held by other workloads)"
	if r.Message != want {
		t.Errorf("got %q, want %q", r.Message, want)
	}
}

// isolcpus written for an SMT-off boot isolates one thread of each core. A
// request for isolation cannot use such a core, and the refusal has to point at
// isolcpus rather than leave a pool with isolated CPUs looking merely full.
func TestAllocate_IsolatedShortageNamesHalfIsolatedCores(t *testing.T) {
	p := testPlacer(t, fourCoresSMT2Interleaved(), 1, lcpus(2, 3))
	r := allocate(t, p, Request{UUID: u("iso"), NumVCPUs: 2, Mode: ModeWholeCoreSMT,
		NUMA: NUMAAllowCross, RequireIsolated: true})
	if r.Status != Insufficient {
		t.Fatalf("no core is wholly isolated, want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "2 cores are only partly kernel-isolated") {
		t.Errorf("the shortage must name the half-isolated cores, got %q", r.Message)
	}
	// An ordinary request keeps off them too: they touch the isolated set.
	o := allocate(t, p, Request{UUID: u("ordinary"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if o.Status != Insufficient || !strings.Contains(o.Message, "2 cores are kernel-isolated") {
		t.Errorf("want Insufficient naming the isolated cores, got %v (%s)", o.Status, o.Message)
	}
}

// isolcpus is the operator's, so EVE cannot refuse it, but the two ways it can
// fight placement have to be told at startup: an isolated CPU EVE reserves for
// itself, and a core isolated on one thread only. Both are warnings for the
// isolated pool, which the caller stamps with the time it found them.
func TestIsolationIssues(t *testing.T) {
	topo := fourCoresSMT2Interleaved() // core c is lcpus c and c+4
	if got := testPlacer(t, topo, 1, lcpus(2, 3, 6, 7)).IsolationIssues(); len(got) != 0 {
		t.Errorf("whole isolated cores clear of the reserved range are fine, got %+v", got)
	}
	if got := testPlacer(t, topo, 1, nil).IsolationIssues(); len(got) != 0 {
		t.Errorf("a node that isolates nothing has nothing to report, got %+v", got)
	}
	got := testPlacer(t, topo, 1, lcpus(0, 4, 3, 2)).IsolationIssues()
	if len(got) != 2 {
		t.Fatalf("want one issue for the reserved CPU and one for the half cores, got %+v", got)
	}
	if got[0].Issue != types.CPUPoolIssueReservedCPUs ||
		!strings.Contains(got[0].Error, "CPUs [0], which are reserved for EVE") ||
		strings.Contains(got[0].Error, "eve_max_vcpus") {
		t.Errorf("the reserved CPU must be named, got %+v", got[0])
	}
	if got[1].Issue != types.CPUPoolIssuePartialCore ||
		!strings.Contains(got[1].Error, "CPUs [2 3] but not their SMT siblings [6 7]") {
		t.Errorf("the half-isolated cores must be named with their siblings, got %+v", got[1])
	}
	for _, w := range got {
		if w.ErrorSeverity != types.ErrorSeverityWarning || w.ErrorRetryCondition == "" ||
			!w.ErrorTime.IsZero() {
			t.Errorf("want an unstamped warning with a retry condition, got %+v", w)
		}
	}
	// The reserved set is wherever EVE's CPUs are, not a low range.
	p, err := NewPlacer(topo, lcpus(3, 7), lcpus(3, 7))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.IsolationIssues(); len(got) != 1 || got[0].Issue != types.CPUPoolIssueReservedCPUs ||
		!strings.Contains(got[0].Error, "CPUs [3 7], which are reserved for EVE") {
		t.Errorf("want the reserved core 3 named, got %+v", got)
	}
}

// An ordinary shortage names the cores other workloads hold alongside the
// structural reasons, so the operator can tell "the node is busy" from "the
// node can never fit this".
func TestAllocate_ShortageNamesHeldCores(t *testing.T) {
	p := testPlacer(t, fourCoresSMT2Interleaved(), 1, nil)
	if r := allocate(t, p, Request{UUID: u("a"), NumVCPUs: 4, Mode: ModeWholeCoreSMT,
		NUMA: NUMAAllowCross}); r.Status != Success {
		t.Fatalf("cores 1-3 are free, got %v (%s)", r.Status, r.Message)
	}
	r := allocate(t, p, Request{UUID: u("b"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	want := "need 2 free cores, have 1 (2 are held by other workloads; " +
		"1 cores are partly reserved for EVE and cannot be handed out whole)"
	if r.Status != Insufficient || r.Message != want {
		t.Errorf("got %v %q, want Insufficient %q", r.Status, r.Message, want)
	}
}

// A shortage caused by hybrid single-thread cores must name that reason too, and
// must say it in terms of the thread count that was skipped: cores are dropped
// whenever their thread count differs from the request, which also covers
// 4-thread cores that do have siblings. SMT-capable cores exist, so this is a
// shortage, not an unsupported request.
func TestAllocate_ShortageNamesCoresWithWrongThreadCount(t *testing.T) {
	p := testPlacer(t, hybridTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("smt"), NumVCPUs: 8, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "do not have exactly 2 hardware threads") {
		t.Errorf("shortage must explain the skipped cores, got %q", r.Message)
	}
	// 8 vCPUs = 4 cores; only the two SMT P-cores can serve them.
	if r.CoresNeeded != 4 || r.CoresFree != 2 {
		t.Errorf("want CoresNeeded=4 CoresFree=2, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

// Reserving every CPU for EVE is a misconfiguration, not a runtime state: it
// must fail at construction rather than turn every later placement into an
// unexplained shortage. A CPU the topology lacks reserves nothing.
func TestNewPlacer_RejectsOverReservation(t *testing.T) {
	topo := fourCoresSMT2Interleaved() // 8 logical CPUs
	all := lcpus(0, 1, 2, 3, 4, 5, 6, 7)
	for _, reserved := range [][]cputopology.LCPU{all, append(lcpus(99, 3), all...)} {
		if _, err := NewPlacer(topo, reserved, nil); err == nil {
			t.Errorf("reserving %v of 8 CPUs must be rejected", reserved)
		}
	}
	for _, reserved := range [][]cputopology.LCPU{nil, lcpus(0, 1, 2, 3, 4, 5, 6),
		lcpus(0, 1, 2, 3, 4, 5, 6, 99)} {
		if _, err := NewPlacer(topo, reserved, nil); err != nil {
			t.Errorf("reserving %v still leaves a CPU, must be accepted: %v", reserved, err)
		}
	}
	if _, err := NewPlacer(nil, nil, nil); err == nil {
		t.Error("a nil topology must be rejected")
	}
	if _, err := NewPlacer(cputopology.Build(nil), nil, nil); err == nil {
		t.Error("a topology with no CPUs must be rejected")
	}
}

// A workload holds one assignment at a time: a second Claim for it is refused
// whatever it names, without reading as a wait for taken CPUs, and changes
// nothing.
func TestClaim_SecondClaimBySameIDRejected(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	req := Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}
	if r := allocate(t, p, req); r.Status != Success {
		t.Fatalf("first allocate should succeed, got %v", r.Status)
	}
	before := p.Holders()
	again := p.Propose(req)
	if again.Status != Success {
		t.Fatalf("free cores remain, want a proposal, got %v (%s)", again.Status, again.Message)
	}
	if err := p.Claim(req.UUID, again.Assignment); err == nil || errors.Is(err, errTaken) {
		t.Fatalf("re-claiming for the same UUID must be refused as already holding, got %v", err)
	}
	if !maps.Equal(before, p.Holders()) {
		t.Errorf("a refused claim must change nothing: %v -> %v", before, p.Holders())
	}
}

func TestAllocate_AllowCrossSpansNodes(t *testing.T) {
	p := testPlacer(t, twoNodesOneCoreEach(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Success {
		t.Fatalf("allow-cross should span both nodes and succeed, got %v (%s)", r.Status, r.Message)
	}
	if nodes := numaNodes(p.topo, r.Assignment); len(nodes) != 2 {
		t.Fatalf("want assignment spanning 2 NUMA nodes, got %v", nodes)
	}
	if len(r.Assignment.OrderedHostCPUs) != 4 {
		t.Fatalf("want 4 host cpus, got %d", len(r.Assignment.OrderedHostCPUs))
	}
}

func TestAllocate_ParkedSiblingBlocksReuse(t *testing.T) {
	p := testPlacer(t, oneCoreTopo(), 0, nil)
	if r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("first one-per-core should succeed, got %v", r.Status)
	}
	r := allocate(t, p, Request{UUID: u("vm2"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Insufficient {
		t.Fatalf("parked sibling must block core reuse -> Insufficient, got %v (%s)", r.Status, r.Message)
	}
}

func TestAllocate_ThreadGranular(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	got, err := allocShared(t, p, "legacy", 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("want 3 cpus, got %v err %v", got, err)
	}
	if len(dedicatedSet(p)) != 3 {
		t.Fatalf("shared alloc must be in dedicated set")
	}
}

func TestAllocate_ThreadGranularSkipsReserved(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 2, nil) // reserve lcpus 0,1
	got, err := allocShared(t, p, "legacy", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] < 2 {
		t.Fatalf("must skip reserved cpus 0,1, got %v", got)
	}
}

// A core only partly isolated serves no placement: a thread-granular request
// keeps off its other thread as a whole-core request keeps off the core, and
// a shortage names both kinds of CPU it passed over.
func TestAllocate_ThreadGranularSkipsHalfIsolatedCores(t *testing.T) {
	// Cores 2 and 3 isolated on one thread (lcpus 2, 3), not the other (6, 7).
	p := testPlacer(t, fourCoresSMT2Interleaved(), 1, lcpus(2, 3))
	got, err := allocShared(t, p, "fits", 3)
	if err != nil || !reflect.DeepEqual(got, []cputopology.LCPU{1, 4, 5}) {
		t.Fatalf("want [1 4 5], the CPUs of the cores with no isolated thread, got %v (%v)", got, err)
	}
	r := allocate(t, p, Request{UUID: u("short"), NumVCPUs: 1, Mode: ModeShared})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	for _, want := range []string{"CPUs [2 3] are kernel-isolated", "CPUs [6 7] share a core"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("the shortage must say %q, got %q", want, r.Message)
		}
	}
}

func TestMixed_NoOverlap_TopologyThenShared(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatal(r.Message)
	}
	// collect vm1's cpus
	vm1 := map[uint32]bool{}
	for _, c := range p.dedicated[u("vm1")] {
		vm1[uint32(c)] = true
	}
	got, err := allocShared(t, p, "legacy", 8)
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
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	shared, _ := allocShared(t, p, "legacy", 2)
	sharedSet := map[uint32]bool{}
	for _, c := range shared {
		sharedSet[uint32(c)] = true
	}
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
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
	infos := []cputopology.CPU{
		{ID: 0, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 1, Socket: 0, Core: 0, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 2, Socket: 0, Core: 1, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
		{ID: 3, Socket: 0, Core: 1, NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true}},
	}
	for i := 0; i < 4; i++ {
		infos = append(infos, cputopology.CPU{
			ID: cputopology.LCPU(4 + i), Socket: 0, Core: uint(2 + i), NUMA: 0, L3: cputopology.CacheID{ID: 0, Known: true},
		})
	}
	return cputopology.Build(infos)
}

// whole-core-smt must place a vCPU on each SMT sibling of ONE physical core and
// never satisfy the request with a single-thread (E) core, which cannot present
// threads=2. Regression for the hybrid-CPU count mismatch (ordered < vCPUs).
func TestAllocate_WholeCoreSMT_HybridSkipsSingleThread(t *testing.T) {
	p := testPlacer(t, hybridTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
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
	c0 := p.topo.CoreOf(a.OrderedHostCPUs[0])
	c1 := p.topo.CoreOf(a.OrderedHostCPUs[1])
	if c0.Socket != c1.Socket || c0.ID != c1.ID {
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
	p := testPlacer(t, hybridTopo(), 4, nil) // reserve lcpu 0-3 -> both P-cores excluded
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Insufficient {
		t.Fatalf("no full-SMT core free must be Insufficient, got %v (%s)", r.Status, r.Message)
	}
}

// one-per-core may use single-thread E-cores (one vCPU per physical core, no
// sibling to park).
func TestAllocate_OnePerCore_UsesSingleThreadCores(t *testing.T) {
	p := testPlacer(t, hybridTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if len(a.OrderedHostCPUs) != 4 {
		t.Fatalf("one-per-core must map one host CPU per vCPU (4), got %v", a.OrderedHostCPUs)
	}
	usedECore := false
	for _, c := range a.OrderedHostCPUs {
		if len(p.topo.CoreOf(c).Siblings) == 1 {
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
	p := testPlacer(t, hybridTopo(), 0, nil)
	if r := allocate(t, p, Request{UUID: u("smt"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("whole-core-smt vm should succeed, got %v (%s)", r.Status, r.Message)
	}
	if r := allocate(t, p, Request{UUID: u("opc"), NumVCPUs: 4, Mode: ModeOnePerCore, NUMA: NUMALocal}); r.Status != Success {
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
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if nodes := numaNodes(p.topo, r.Assignment); len(nodes) != 1 {
		t.Fatalf("best-effort should stay on one node when it fits, got %v", nodes)
	}
}

// best-effort falls back to spanning nodes rather than failing when no single
// node fits (contrast NUMALocal, which returns NeedsRebalance here).
func TestAllocate_BestEffort_FallsBackToSpanning(t *testing.T) {
	p := testPlacer(t, twoNodesOneCoreEach(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("best-effort must fall back to spanning, got %v (%s)", r.Status, r.Message)
	}
	if nodes := numaNodes(p.topo, r.Assignment); len(nodes) != 2 {
		t.Fatalf("expected spanning 2 nodes, got %v", nodes)
	}
}

// threeNodesThreeCores is three NUMA nodes of three SMT2 cores each: node n is
// lcpus 6n..6n+5, core c of it lcpus 6n+2c and 6n+2c+1.
func threeNodesThreeCores() *cputopology.Topology {
	var infos []cputopology.CPU
	for lc := uint(0); lc < 18; lc++ {
		node := lc / 6
		infos = append(infos, cputopology.CPU{
			ID: cputopology.LCPU(lc), Socket: node, Core: (lc % 6) / 2, NUMA: node, L3: cputopology.CacheID{ID: uint32(node), Known: true},
		})
	}
	return cputopology.Build(infos)
}

// When no node can hold it, best-effort spans as few nodes as can: with one
// core left on node 0 and three on nodes 1 and 2, five cores fit on nodes 1
// and 2, not on all three as taking nodes in order would have it. No NUMA
// consideration at all (NUMAAllowCross) still takes them in node order.
func TestAllocate_BestEffort_SpansFewestNodes(t *testing.T) {
	for _, tc := range []struct {
		numa NUMAPolicy
		want []uint
	}{
		{NUMABestEffort, []uint{1, 2}},
		{NUMAAllowCross, []uint{0, 1, 2}},
	} {
		p := testPlacer(t, threeNodesThreeCores(), 0, nil)
		mustClaim(t, p, u("busy"), 0, 1, 2, 3)
		r := allocate(t, p, Request{UUID: u("big"), NumVCPUs: 10, Mode: ModeWholeCoreSMT, NUMA: tc.numa})
		if r.Status != Success {
			t.Fatalf("NUMA policy %v: 7 cores are free, want Success, got %v (%s)", tc.numa, r.Status, r.Message)
		}
		if got := numaNodes(p.topo, r.Assignment); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("NUMA policy %v: got nodes %v, want %v", tc.numa, got, tc.want)
		}
	}
}

// A request that leaves NUMA unset is placed best effort, what the API's
// unspecified numa_policy means: spanning as few nodes as hold it, neither
// refused as single-node would be nor spread in node order as none would.
func TestPropose_NUMADefaultIsBestEffort(t *testing.T) {
	var unset Request
	if unset.NUMA != NUMABestEffort || unset.NUMA.String() != "best-effort" {
		t.Fatalf("the zero NUMAPolicy must be best effort, got %v", unset.NUMA)
	}
	p := testPlacer(t, threeNodesThreeCores(), 0, nil)
	mustClaim(t, p, u("busy"), 0, 1, 2, 3)
	r := p.Propose(Request{UUID: u("big"), NumVCPUs: 10, Mode: ModeWholeCoreSMT})
	if r.Status != Success {
		t.Fatalf("7 cores are free, want Success, got %v (%s)", r.Status, r.Message)
	}
	if got := numaNodes(p.topo, r.Assignment); !reflect.DeepEqual(got, []uint{1, 2}) {
		t.Errorf("want the fewest nodes [1 2], got %v", got)
	}
	span := testPlacer(t, twoNodesOneCoreEach(), 0, nil).Propose(
		Request{UUID: u("span"), NumVCPUs: 4, Mode: ModeWholeCoreSMT})
	if span.Status != Success {
		t.Errorf("no node holds it, want a placement spanning both, got %v (%s)", span.Status, span.Message)
	}
}

// Propose decides and changes nothing, whatever it decides: only Claim makes
// CPUs held, so proposing again gives the same answer.
func TestPropose_ChangesNothing(t *testing.T) {
	p := testPlacer(t, hybridTopo(), 0, nil)
	mustClaim(t, p, u("held"), 0, 1)
	before := p.Holders()
	for _, r := range []Request{
		{UUID: u("smt"), NumVCPUs: 2, Mode: ModeWholeCoreSMT},
		{UUID: u("opc"), NumVCPUs: 2, Mode: ModeOnePerCore},
		{UUID: u("shared"), NumVCPUs: 3, Mode: ModeShared},
		{UUID: u("short"), NumVCPUs: 8, Mode: ModeOnePerCore},
		{UUID: u("odd"), NumVCPUs: 3, Mode: ModeWholeCoreSMT},
	} {
		first, second := p.Propose(r), p.Propose(r)
		if first.Status != second.Status || !reflect.DeepEqual(first.Assignment, second.Assignment) {
			t.Errorf("%v x%d: proposing twice gave %v %+v, then %v %+v", r.Mode, r.NumVCPUs,
				first.Status, first.Assignment, second.Status, second.Assignment)
		}
		if p.Holds(r.UUID) || !maps.Equal(before, p.Holders()) {
			t.Errorf("%v x%d (%v): Propose changed the holders %v -> %v", r.Mode, r.NumVCPUs,
				first.Status, before, p.Holders())
		}
	}
}

// Propose holds nothing, so two proposals can name the same CPUs: the first
// Claim wins, the second is told they are taken and holds nothing, and a fresh
// proposal places it around the winner.
func TestClaim_SecondProposalOfTheSameCPUsIsTaken(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	req := func(id string) Request {
		return Request{UUID: u(id), NumVCPUs: 2, Mode: ModeWholeCoreSMT}
	}
	a, b := p.Propose(req("a")), p.Propose(req("b"))
	if a.Status != Success || b.Status != Success {
		t.Fatalf("want two proposals, got %v (%s) and %v (%s)", a.Status, a.Message, b.Status, b.Message)
	}
	if !slices.Equal(a.Assignment.CPUs(), b.Assignment.CPUs()) {
		t.Fatalf("nothing was held in between, want the same CPUs, got %v and %v",
			a.Assignment.CPUs(), b.Assignment.CPUs())
	}
	if err := p.Claim(u("a"), a.Assignment); err != nil {
		t.Fatal(err)
	}
	if err := p.Claim(u("b"), b.Assignment); !errors.Is(err, errTaken) {
		t.Fatalf("want errTaken for CPUs a holds, got %v", err)
	}
	if p.Holds(u("b")) {
		t.Fatal("a refused claim must hold nothing")
	}
	again := allocate(t, p, req("b"))
	if again.Status != Success {
		t.Fatalf("free cores remain, got %v (%s)", again.Status, again.Message)
	}
	for _, c := range again.Assignment.CPUs() {
		if slices.Contains(a.Assignment.CPUs(), c) {
			t.Errorf("b was placed on CPU %d, which a holds", c)
		}
	}
}

// Claiming a running workload's CPUs from its status reseeds a fresh placer
// (post-restart), so it does not hand them to another VM; Free returns them to
// the pool.
func TestClaim_ReseedBlocksAndFrees(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil) // 16 lcpus
	running := &Assignment{OrderedHostCPUs: lcpus(0, 1, 2, 3),
		Guest: types.CPUTopology{Sockets: 1, Cores: 2, Threads: 2}}
	if err := p.Claim(u("running"), running); err != nil {
		t.Fatalf("Claim of a running VM's cores: %v", err)
	}
	if len(freeCPUs(p)) != 16-4 {
		t.Fatalf("claimed cpus must be excluded from FreeCPUs, got %d", len(freeCPUs(p)))
	}
	r := allocate(t, p, Request{UUID: u("new"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("new VM should allocate around the claimed cores, got %v (%s)", r.Status, r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if c <= 3 {
			t.Fatalf("new VM got a claimed core %d", c)
		}
	}
	p.Free(u("running"))
	if len(freeCPUs(p)) != 16-len(r.Assignment.OrderedHostCPUs) {
		t.Fatalf("after Free, claimed cores must return to the free pool")
	}
}

// A claim reseeded from persisted DomainStatus is where a stale or conflicting
// assignment can appear. Recording one verbatim would let two workloads own a
// CPU and the allocator hand it out twice, so every claim the placer cannot
// honour is refused -- and refused without changing anything. Only a CPU held
// by another workload is errTaken; the rest are faults in the assignment.
func TestClaim_RejectsClaimsItCannotHonour(t *testing.T) {
	running, other := u("running"), u("other")

	newSeeded := func(t *testing.T) *Placer {
		t.Helper()
		p := testPlacer(t, twoSocketTopo(), 0, nil) // lcpus 0..15, core {2c, 2c+1}
		mustClaim(t, p, running, 0, 1)
		return p
	}
	oneCore := types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2}

	tests := []struct {
		name  string
		id    uuid.UUID
		a     *Assignment
		taken bool
	}{
		{"an empty CPU set claims nothing", other, &Assignment{}, false},
		{"a logical CPU the host does not have", other,
			&Assignment{OrderedHostCPUs: lcpus(99)}, false},
		{"a parked CPU the host does not have", other,
			&Assignment{OrderedHostCPUs: lcpus(2), ParkedCPUs: lcpus(99)}, false},
		{"one CPU serving two vCPUs", other,
			&Assignment{OrderedHostCPUs: lcpus(2, 2)}, false},
		{"a CPU both parked and running a vCPU", other,
			&Assignment{OrderedHostCPUs: lcpus(2), ParkedCPUs: lcpus(2)}, false},
		{"a guest topology the vCPUs do not match", other,
			&Assignment{OrderedHostCPUs: lcpus(2, 3, 4), Guest: oneCore}, false},
		{"a CPU another workload already holds", other,
			&Assignment{OrderedHostCPUs: lcpus(1)}, true},
		{"a parked CPU another workload already holds", other,
			&Assignment{OrderedHostCPUs: lcpus(2), ParkedCPUs: lcpus(0)}, true},
		{"a second, different claim by the same id", running,
			&Assignment{OrderedHostCPUs: lcpus(2, 3), Guest: oneCore}, false},
		{"a claim that only partly overlaps its own", running,
			&Assignment{OrderedHostCPUs: lcpus(0, 1, 2)}, false},
		{"replaying its own claim", running,
			&Assignment{OrderedHostCPUs: lcpus(1, 0)}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newSeeded(t)
			before := p.Holders()
			err := p.Claim(tc.id, tc.a)
			if err == nil {
				t.Fatalf("Claim(%s, %+v) must be rejected", tc.id, tc.a)
			}
			if errors.Is(err, errTaken) != tc.taken {
				t.Errorf("errors.Is(err, errTaken) = %v, want %v: %v", !tc.taken, tc.taken, err)
			}
			if !maps.Equal(before, p.Holders()) || (tc.id != running && p.Holds(tc.id)) {
				t.Errorf("a rejected Claim must change nothing: %v -> %v", before, p.Holders())
			}
		})
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
	var infos []cputopology.CPU
	for core := uint(0); core < 4; core++ {
		infos = append(infos, cputopology.CPU{ID: cputopology.LCPU(core), Core: core})
	}
	return cputopology.Build(infos)
}

// A whole-core-SMT request on a node with no SMT-capable core at all is
// unsatisfiable, not short of capacity. Reported as a shortage it produced advice
// -- stop another pinned workload, get a node with more cores -- of which every
// clause is false here, sending the operator after capacity that could never
// help. This is the likeliest failure of the default pinning policy.
func TestAllocate_WholeCoreSMT_NoSMTAnywhereIsUnsatisfiable(t *testing.T) {
	p := testPlacer(t, noSMTTopo(), 0, nil)
	r := allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != TopologyUnsupported {
		t.Fatalf("the node cannot satisfy this in any arrangement, want TopologyUnsupported, got %v (%s)",
			r.Status, r.Message)
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
	if len(dedicatedSet(p)) != 0 {
		t.Errorf("a refused request must reserve nothing, got %v", dedicatedSet(p))
	}
	if opc := allocate(t, p, Request{UUID: u("opc"), NumVCPUs: 2, Mode: ModeOnePerCore,
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
	p := testPlacer(t, twoCoresSMT2(), 0, nil) // cores {0,4} and {1,5}
	if r := allocate(t, p, Request{UUID: u("holder"), NumVCPUs: 4, Mode: ModeWholeCoreSMT,
		NUMA: NUMABestEffort}); r.Status != Success {
		t.Fatalf("holder must take both cores, got %v (%s)", r.Status, r.Message)
	}
	r := allocate(t, p, Request{UUID: u("late"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Insufficient {
		t.Fatalf("the cores exist and are merely busy, want Insufficient, got %v (%s)", r.Status, r.Message)
	}
	if r.CoresNeeded != 1 || r.CoresFree != 0 {
		t.Errorf("want CoresNeeded=1 CoresFree=0, got %d/%d", r.CoresNeeded, r.CoresFree)
	}
}

// The SMT sibling parked by a one-per-core request is held, not idle capacity:
// handing it to anyone else gives back exactly the interference the mode exists
// to remove. Every view of the node must agree it is taken.
func TestAllocate_OnePerCore_ParkedSiblingIsWithheldEverywhere(t *testing.T) {
	p := testPlacer(t, twoCoresSMT2(), 0, nil) // cores {0,4} and {1,5}
	r := allocate(t, p, Request{UUID: u("opc"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.ParkedCPUs) != 1 {
		t.Fatalf("want exactly one parked sibling, got %v", r.Assignment.ParkedCPUs)
	}
	parked := r.Assignment.ParkedCPUs[0]

	for _, c := range freeCPUs(p) {
		if c == parked {
			t.Errorf("parked sibling %d must not be free, got %v", parked, freeCPUs(p))
		}
	}
	shared, err := allocShared(t, p, "legacy", 2)
	if err != nil {
		t.Fatalf("the remaining whole core must still serve a shared request: %v", err)
	}
	for _, c := range shared {
		if c == parked {
			t.Errorf("shared allocation took the parked sibling %d: %v", parked, shared)
		}
	}
	dedicated := poolByKind(t, p.Pools(), types.CPUPoolKindDedicated)
	if !slices.Contains(dedicated.CPUs, uint32(parked)) {
		t.Errorf("parked sibling %d must be reported in the dedicated pool, got %v",
			parked, dedicated.CPUs)
	}
	if len(dedicated.FreeCPUs) != 0 {
		t.Errorf("nothing in the dedicated pool is free, got free CPUs %v",
			dedicated.FreeCPUs)
	}
}

// The guest -smp topology and the host CPU list are two views of one decision and
// nothing downstream cross-checks them: an inconsistency reaches the operator as
// a domain that will not start. validate is the only place that can catch it, so
// each way of getting it wrong must be caught.
func TestAssignment_ValidateRejectsInconsistentPlacements(t *testing.T) {
	topo := twoNodesOneCoreEach() // core {0,1} in node 0, core {2,3} in node 1

	for _, good := range []*Assignment{
		{OrderedHostCPUs: lcpus(0, 1), Guest: types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2}},
		// A thread-granular placement has no guest topology to match.
		{OrderedHostCPUs: lcpus(0, 2, 3)},
	} {
		if err := good.validate(topo); err != nil {
			t.Fatalf("a consistent assignment must validate: %+v: %v", good, err)
		}
	}

	tests := []struct {
		name string
		a    *Assignment
	}{
		{"no host CPUs at all", &Assignment{}},
		{"vCPU count disagrees with the guest topology", &Assignment{
			OrderedHostCPUs: lcpus(0, 1, 2),
			Guest:           types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2},
		}},
		{"one host CPU serving two vCPUs", &Assignment{
			OrderedHostCPUs: lcpus(0, 0),
			Guest:           types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2},
		}},
		{"a CPU both parked and running a vCPU", &Assignment{
			OrderedHostCPUs: lcpus(0, 1),
			Guest:           types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2},
			ParkedCPUs:      lcpus(1),
		}},
		{"a host CPU the topology does not have", &Assignment{
			OrderedHostCPUs: lcpus(0, 99),
			Guest:           types.CPUTopology{Sockets: 1, Cores: 1, Threads: 2},
		}},
		{"a parked CPU the topology does not have", &Assignment{
			OrderedHostCPUs: lcpus(0),
			Guest:           types.CPUTopology{Sockets: 1, Cores: 1, Threads: 1},
			ParkedCPUs:      lcpus(99),
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

// Every assignment Propose returns must pass its own consistency check, across
// the modes and NUMA policies that build one differently.
func TestPropose_SuccessfulAssignmentsAreConsistent(t *testing.T) {
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
		{"thread-granular", hybridTopo(),
			Request{UUID: u("e"), NumVCPUs: 5, Mode: ModeShared}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPlacer(t, tc.topo, 0, nil)
			res := p.Propose(tc.r)
			if res.Status != Success {
				t.Fatalf("want Success, got %v (%s)", res.Status, res.Message)
			}
			if err := res.Assignment.validate(p.topo); err != nil {
				t.Errorf("Propose returned an inconsistent assignment: %v", err)
			}
		})
	}
}

func TestFreeCPUs_ExcludesBoth(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)                                                       // 16 lcpus total
	_ = allocate(t, p, Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}) // 4 lcpus
	_, _ = allocShared(t, p, "legacy", 2)                                                             // 2 lcpus
	free := freeCPUs(p)
	if len(free) != 16-4-2 {
		t.Fatalf("FreeCPUs should exclude both allocations: got %d", len(free))
	}
	p.Free(u("vm1"))
	p.Free(u("legacy"))
	if len(freeCPUs(p)) != 16 {
		t.Fatalf("after Free all cpus should be free")
	}
}

// Claim holds a planned assignment only if all of it is free, in one step,
// and says which CPU is taken when it is not.
func TestClaim_AllOrNothing(t *testing.T) {
	p := testPlacer(t, fourCoresSMT2Interleaved(), 0, nil) // core c is CPUs c and c+4
	plan := p.Plan([]Request{{UUID: u("a"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross}})
	a := plan[u("a")].Assignment
	mustClaim(t, p, u("squatter"), uint32(a.OrderedHostCPUs[1]))
	if err := p.Claim(u("a"), a); !errors.Is(err, errTaken) {
		t.Fatalf("want errTaken while a planned CPU is held, got %v", err)
	}
	if p.Holds(u("a")) {
		t.Fatal("a refused claim must reserve nothing")
	}
	p.Free(u("squatter"))
	if err := p.Claim(u("a"), a); err != nil {
		t.Fatalf("the slot is free, want the claim to succeed: %v", err)
	}
	if got := p.Holders(); got[a.OrderedHostCPUs[0]] != u("a") || got[a.OrderedHostCPUs[1]] != u("a") {
		t.Errorf("want both CPUs held by a, got %v", got)
	}
}

// A request placed off its plan stays off the CPUs planned for others, whole
// cores and thread-granular alike, and the shortage says so.
func TestAllocate_AvoidsPlannedCPUs(t *testing.T) {
	p := testPlacer(t, fourCoresSMT2Interleaved(), 0, nil)
	avoid := []cputopology.LCPU{1, 5, 2, 6} // cores 1 and 2
	r := allocate(t, p, Request{UUID: u("whole"), NumVCPUs: 4, Mode: ModeWholeCoreSMT,
		NUMA: NUMAAllowCross, Avoid: avoid})
	if r.Status != Success {
		t.Fatalf("cores 0 and 3 are free, got %v (%s)", r.Status, r.Message)
	}
	for _, c := range r.Assignment.CPUs() {
		if slices.Contains(avoid, c) {
			t.Errorf("took planned CPU %d: %v", c, r.Assignment.CPUs())
		}
	}
	short := allocate(t, p, Request{UUID: u("more"), NumVCPUs: 2, Mode: ModeWholeCoreSMT,
		NUMA: NUMAAllowCross, Avoid: avoid})
	if short.Status != Insufficient || !strings.Contains(short.Message, "2 are planned for workloads not started yet") {
		t.Errorf("want a shortage naming the planned cores, got %v (%s)", short.Status, short.Message)
	}
	thread := allocate(t, p, Request{UUID: u("thread"), NumVCPUs: 1, Mode: ModeShared, Avoid: avoid})
	if thread.Status != Insufficient || !strings.Contains(thread.Message, "are planned for workloads") {
		t.Errorf("want a thread-granular shortage naming the planned CPUs, got %v (%s)", thread.Status, thread.Message)
	}
}

// The housekeeping set is every free CPU but the isolated ones, falling back to
// all of them, flagged, when only isolated CPUs are left.
func TestHousekeepingCPUs(t *testing.T) {
	p := testPlacer(t, fourCoresSMT2Interleaved(), 2, lcpus(1, 5, 3, 7))
	if hk, only := p.HousekeepingCPUs(); only || !slices.Equal(hk, []cputopology.LCPU{0, 2, 4, 6}) {
		t.Errorf("want [0 2 4 6], got %v (isolatedOnly=%v)", hk, only)
	}
	mustClaim(t, p, u("all"), 0, 2, 4, 6)
	if hk, only := p.HousekeepingCPUs(); !only || !slices.Equal(hk, []cputopology.LCPU{1, 3, 5, 7}) {
		t.Errorf("only isolated CPUs are free, want them flagged, got %v (isolatedOnly=%v)", hk, only)
	}
}

// A synthesized topology cannot tell SMT siblings apart: the placer gives no
// workload CPUs of its own and reports no pools, while the shared workloads
// still get every CPU.
func TestPlacer_RefusesDegradedTopology(t *testing.T) {
	topo := cputopology.Build([]cputopology.CPU{{ID: 0, Core: 0}, {ID: 1, Core: 1}})
	topo.Degraded = true
	p := testPlacer(t, topo, 0, nil)
	if !p.Degraded() {
		t.Error("the placer must report the degraded topology")
	}
	for _, mode := range []PinMode{ModeShared, ModeOnePerCore} {
		r := p.Propose(Request{UUID: u("x"), NumVCPUs: 1, Mode: mode})
		if r.Status != TopologyUnsupported {
			t.Errorf("%v: want a refusal for an unknown topology, got %v (%s)", mode, r.Status, r.Message)
		}
	}
	if pools := p.Pools(); pools != nil {
		t.Errorf("want no pools on a synthesized topology, got %+v", pools)
	}
	if hk, _ := p.HousekeepingCPUs(); len(hk) != 2 {
		t.Errorf("shared workloads still run on every CPU, got %v", hk)
	}
}

func TestClaim_NilAssignment(t *testing.T) {
	p := testPlacer(t, twoSocketTopo(), 0, nil)
	if err := p.Claim(u("nil"), nil); err == nil || errors.Is(err, errTaken) {
		t.Fatalf("Claim(nil) = %v, want a validation error", err)
	}
	if p.Holds(u("nil")) {
		t.Fatal("a refused claim recorded CPUs")
	}
}
