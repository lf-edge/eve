// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	uuid "github.com/satori/go.uuid"
)

// PinMode selects how a pinned VM's vCPUs map onto physical cores.
type PinMode int

const (
	ModeShared       PinMode = iota // thread-granular: single logical CPUs, not whole cores
	ModeWholeCoreSMT                // both SMT siblings of each core are vCPUs (guest threads=2)
	ModeOnePerCore                  // one vCPU per physical core; sibling parked (guest threads=1)
)

// String returns the name used in logs and cpuplan.json.
func (m PinMode) String() string {
	switch m {
	case ModeShared:
		return "shared"
	case ModeWholeCoreSMT:
		return "whole-core-smt"
	case ModeOnePerCore:
		return "one-per-core"
	default:
		return fmt.Sprintf("PinMode(%d)", int(m))
	}
}

// NUMAPolicy selects NUMA placement strictness.
type NUMAPolicy int

const (
	NUMALocal      NUMAPolicy = iota // all cores in one NUMA node, else NeedsRebalance (K8s single-numa-node/restricted)
	NUMAAllowCross                   // no NUMA affinity; may span nodes freely (K8s none)
	NUMABestEffort                   // prefer one NUMA node, else span as few as fit (K8s best-effort)
)

// String returns the K8s Topology Manager policy name this maps to (also the
// name used in logs).
func (n NUMAPolicy) String() string {
	switch n {
	case NUMALocal:
		return "single-numa-node"
	case NUMAAllowCross:
		return "none"
	case NUMABestEffort:
		return "best-effort"
	default:
		return fmt.Sprintf("NUMAPolicy(%d)", int(n))
	}
}

// Request is a single VM's placement request.
type Request struct {
	UUID     uuid.UUID
	NumVCPUs int
	Mode     PinMode
	NUMA     NUMAPolicy
	// RequireIsolated restricts placement to physical cores the running kernel
	// isolates, and is the only way to be given one. It is a hard constraint,
	// not a preference: a request that sets it and cannot be served from the
	// isolated set fails rather than landing on an unshielded core, because a
	// workload told it got kernel isolation and placed without it is worse off
	// than one that was refused.
	RequireIsolated bool
	// Avoid are CPUs the request must not take although they are free: those
	// the plan sets aside for workloads that have not started yet. A workload
	// placed off its plan takes them only at the cost of the one they are
	// planned for, which would make the layout depend on start order.
	Avoid []cputopology.LCPU
}

// GuestTopology is the guest-visible -smp topology to emit.
type GuestTopology struct {
	Sockets int
	Cores   int
	Threads int
}

// Assignment is the result of a successful placement.
type Assignment struct {
	OrderedHostCPUs []cputopology.LCPU // guest vCPU i -> OrderedHostCPUs[i]
	Guest           GuestTopology
	ParkedCPUs      []cputopology.LCPU // siblings held idle (ModeOnePerCore)
	NUMANodes       []uint
}

// CPUs is every CPU the assignment occupies: those backing vCPUs and the
// siblings it parks, which are held as well, or another workload could take
// them.
func (a *Assignment) CPUs() []cputopology.LCPU {
	return append(append([]cputopology.LCPU{}, a.OrderedHostCPUs...), a.ParkedCPUs...)
}

// Status is the outcome class of a placement attempt.
type Status int

const (
	// StatusUnspecified is the zero value and means nothing was decided: no
	// placement was attempted, or a Result was never filled in. Success must not
	// be the zero value -- a Result that was dropped, defaulted or never
	// produced would then read as a placement that worked, and a caller would
	// pin a VM to an empty CPU set believing the allocator approved it.
	StatusUnspecified Status = iota
	Success
	NeedsRebalance
	Insufficient
	InvalidRequest
)

// Result carries the outcome of Allocate.
type Result struct {
	Status     Status
	Assignment *Assignment
	Message    string
	// TopologyUnsupported marks a request the node cannot satisfy in any
	// arrangement; freeing CPUs will not help. It accompanies InvalidRequest.
	//
	// It exists to keep a caller from offering capacity advice that cannot
	// apply: telling an operator to stop another workload or add cores is
	// actively misleading when the machine simply has no core shaped the way the
	// request needs (SMT disabled or absent, as on most ARM64 parts).
	TopologyUnsupported bool
	// CoresNeeded and CoresFree quantify a shortage: how many whole physical
	// cores the request needs, and how many the allocator could have drawn on.
	// Set only on the shortage statuses (Insufficient, NeedsRebalance), and only
	// for the pinned modes -- a thread-granular request is not counted in cores.
	//
	// They exist so a caller can state the condition the shortage clears under
	// without parsing Message. The published retry_condition has to give an
	// operator the numbers ("needs 5 cores, 4 are free"), and reconstructing them
	// from a second, independent computation would let the two disagree.
	CoresNeeded int
	CoresFree   int
}

// Placer owns dedicated-core bookkeeping and performs topology-aware
// placement. All methods are safe for concurrent use.
type Placer struct {
	mu sync.Mutex
	// topo and numReservedForEVE are write-once: set by the constructor and only
	// read afterwards. That is the whole reason Plan and Score can run without
	// holding mu. A method that refreshed or replaced the topology would break
	// that and would have to take the lock here *and* in those two.
	topo              *cputopology.Topology
	numReservedForEVE uint32
	// isolated is the set the running kernel keeps off its scheduler domains
	// (isolcpus), write-once like topo. It is a kernel fact the allocator cannot
	// discover for itself, so it is supplied by the caller.
	//
	// These CPUs are reserved capacity, not preferred capacity: they are handed
	// out only to a request that asks for kernel isolation, and withheld from
	// every other workload. Handing them to whoever came first would consume the
	// operator's isolation on a workload that never asked for it and leave the
	// one that needs it unplaceable, which is the whole reason isolcpus was set.
	// Keeping EVE and the non-pinned workloads off them is the caller's half of
	// the bargain -- see the housekeeping set in domainmgr.
	isolated map[cputopology.LCPU]bool
	// degraded is set when the topology was synthesized (Topology.Degraded): it
	// cannot tell SMT siblings apart, so the placer gives no workload CPUs of
	// its own and reports no pools.
	degraded bool
	// dedicated maps UUID -> every LCPU it holds (vCPU cores + parked).
	// Guarded by mu.
	dedicated map[uuid.UUID][]cputopology.LCPU
}

// NewPlacer creates a Placer over the given topology, reserving the lowest
// numReservedForEVE logical CPUs for EVE housekeeping.
//
// isolated is what the running kernel isolates from its scheduler domains, read
// from sysfs by the caller; nil on a node booted without isolcpus. CPUs it names
// that the topology does not have are ignored rather than rejected: the kernel's
// idea of the CPU set and the topology's can differ on a node with CPUs offline,
// and a stray id is not a reason to refuse to place anything at all.
//
// Reserving as many CPUs as the host has (or more) leaves nothing to allocate,
// which is a misconfiguration of the eve_max_vcpus kernel argument rather than
// a runtime condition. It is rejected here so it surfaces once, at startup,
// instead of turning every later placement into an unexplained failure.
func NewPlacer(topo *cputopology.Topology, numReservedForEVE uint32,
	isolated []cputopology.LCPU) (*Placer, error) {
	if topo == nil || topo.NumLCPUs == 0 {
		return nil, fmt.Errorf("no CPU topology to place on")
	}
	if numReservedForEVE >= topo.NumLCPUs {
		return nil, fmt.Errorf("%d CPUs reserved for EVE but the host has only %d: "+
			"no CPU would be left for workloads", numReservedForEVE, topo.NumLCPUs)
	}
	return newPlacer(topo, numReservedForEVE, isolated), nil
}

// newPlacer builds a Placer without validation, for callers that derive one
// from an already-validated Placer.
func newPlacer(topo *cputopology.Topology, numReservedForEVE uint32,
	isolated []cputopology.LCPU) *Placer {
	isolatedSet := make(map[cputopology.LCPU]bool, len(isolated))
	for _, c := range isolated {
		if _, ok := topo.ByLCPU[c]; ok {
			isolatedSet[c] = true
		}
	}
	return &Placer{
		topo:              topo,
		numReservedForEVE: numReservedForEVE,
		isolated:          isolatedSet,
		degraded:          topo.Degraded,
		dedicated:         map[uuid.UUID][]cputopology.LCPU{},
	}
}

// Degraded reports whether the topology was synthesized rather than read, in
// which case the placer gives no workload CPUs of its own.
func (p *Placer) Degraded() bool {
	return p.degraded
}

// IsolatedCPUs returns the kernel-isolated CPUs the placer knows about, those
// the topology actually has, ascending. It is the set every other component has
// to agree on, so it is read from the placer rather than re-read from sysfs.
func (p *Placer) IsolatedCPUs() []cputopology.LCPU {
	out := make([]cputopology.LCPU, 0, len(p.isolated))
	for c := range p.isolated {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// coreIsIsolated reports whether every SMT sibling of a core is kernel-isolated.
// A core only half-isolated is no use to a workload that wants to be left alone:
// the kernel still schedules freely on its other thread, which contends for the
// same execution engine.
func (p *Placer) coreIsIsolated(pc *cputopology.PhysicalCore) bool {
	if len(p.isolated) == 0 {
		return false
	}
	for _, s := range pc.Siblings {
		if !p.isolated[s] {
			return false
		}
	}
	return true
}

// coreTouchesIsolated reports whether any SMT sibling of a core is
// kernel-isolated. A core is withheld from an ordinary request on this weaker
// test, not on coreIsIsolated: giving a workload a core with one isolated
// sibling puts one of its threads on an isolated CPU, which is exactly the CPU
// the operator carved out for something else.
func (p *Placer) coreTouchesIsolated(pc *cputopology.PhysicalCore) bool {
	for _, s := range pc.Siblings {
		if p.isolated[s] {
			return true
		}
	}
	return false
}

// IsolationIssueKind names a way the kernel-isolated set can fail placement's
// model.
type IsolationIssueKind int

const (
	// IsolationIssueReservedCPUs: isolcpus covers CPUs reserved for EVE.
	IsolationIssueReservedCPUs IsolationIssueKind = iota
	// IsolationIssuePartialCore: isolcpus isolates only some threads of a core.
	IsolationIssuePartialCore
)

// IsolationIssue is one mistake in the kernel-isolated set, with a sentence
// for the operator naming the CPUs and what to change.
type IsolationIssue struct {
	Kind    IsolationIssueKind
	Message string
}

// IsolationIssues reports where the kernel-isolated set does not fit
// placement's model, for the operator. The operator writes isolcpus, not EVE,
// and placement already keeps every workload off the CPUs concerned, so these
// are warnings, not refusals; refusing to start would take down the workloads
// that do not care, and the device's management with them.
func (p *Placer) IsolationIssues() []IsolationIssue {
	var issues []IsolationIssue
	var reserved []cputopology.LCPU
	for _, c := range p.IsolatedCPUs() {
		if uint32(c) < p.numReservedForEVE {
			reserved = append(reserved, c)
		}
	}
	if len(reserved) > 0 {
		issues = append(issues, IsolationIssue{IsolationIssueReservedCPUs, fmt.Sprintf(
			"isolcpus isolates CPUs %v, which are reserved for EVE (eve_max_vcpus=%d): "+
				"the kernel no longer balances EVE's own services onto them, so the "+
				"reservation is lost; leave them out of isolcpus",
			reserved, p.numReservedForEVE)})
	}
	// A request for isolation takes whole isolated cores and every other
	// request keeps off a core with an isolated thread, so a core only partly
	// isolated serves no placement at all.
	var half, siblings []cputopology.LCPU
	for i := range p.topo.Cores {
		pc := &p.topo.Cores[i]
		if !p.coreTouchesIsolated(pc) || p.coreIsIsolated(pc) {
			continue
		}
		for _, s := range pc.Siblings {
			if p.isolated[s] {
				half = append(half, s)
			} else {
				siblings = append(siblings, s)
			}
		}
	}
	if len(half) > 0 {
		sort.Slice(half, func(i, j int) bool { return half[i] < half[j] })
		sort.Slice(siblings, func(i, j int) bool { return siblings[i] < siblings[j] })
		issues = append(issues, IsolationIssue{IsolationIssuePartialCore, fmt.Sprintf(
			"isolcpus isolates CPUs %v but not their SMT siblings %v: isolation is "+
				"given by whole core, so these cores serve no pinned workload; list "+
				"both siblings of each core", half, siblings)})
	}
	return issues
}

// Holds reports whether id holds CPUs of its own.
func (p *Placer) Holds(id uuid.UUID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.dedicated[id]
	return ok
}

// Free releases all cores dedicated to id. Safe to call for an unknown id.
func (p *Placer) Free(id uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.dedicated, id)
}

// Reserve records that id already holds the given logical CPUs, without running
// placement. It is used to reseed a freshly created Placer from persisted
// DomainStatus after a domainmgr restart, so a VM that is already running does
// not have its dedicated cores handed to another VM.
//
// Unlike Allocate, the CPU set here comes from persisted state rather than from
// a placement decision, so it is validated. Reserve rejects an empty set, a
// logical CPU the host topology does not have, a CPU another workload already
// holds, and a second claim by the same id for a *different* set. Two statuses
// claiming one CPU would make HolderOf name an arbitrary owner and let the
// allocator hand the same CPU out twice, and the restart path is exactly where
// such a conflict is both plausible and least visible.
//
// Re-reserving the identical set (in any order) is a no-op returning nil, so
// replaying a status is harmless. On error nothing is recorded: a rejected
// Reserve leaves the placer exactly as it was.
func (p *Placer) Reserve(id uuid.UUID, cpus []uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(cpus) == 0 {
		return fmt.Errorf("reserve %s: no CPUs given", id)
	}
	want := make([]cputopology.LCPU, 0, len(cpus))
	for _, c := range cpus {
		lcpu := cputopology.LCPU(c)
		if _, ok := p.topo.ByLCPU[lcpu]; !ok {
			return fmt.Errorf("reserve %s: logical CPU %d is not in the host topology", id, c)
		}
		want = append(want, lcpu)
	}
	for _, c := range want {
		if holder, taken := p.holderOf(c); taken && holder != id {
			return fmt.Errorf("reserve %s: logical CPU %d is already held by %s", id, c, holder)
		}
	}
	if held, ok := p.dedicated[id]; ok {
		if !sameLCPUSet(held, want) {
			return fmt.Errorf("reserve %s: already holds %v, refusing to re-reserve as %v",
				id, held, want)
		}
		return nil
	}
	p.dedicated[id] = want
	return nil
}

// sameLCPUSet compares two CPU lists as multisets: a status replayed with its
// CPUs in a different order describes the same reservation.
func sameLCPUSet(a, b []cputopology.LCPU) bool {
	if len(a) != len(b) {
		return false
	}
	count := make(map[cputopology.LCPU]int, len(a))
	for _, c := range a {
		count[c]++
	}
	for _, c := range b {
		count[c]--
		if count[c] < 0 {
			return false
		}
	}
	return true
}

// Holders maps every held CPU to the workload holding it, as one snapshot.
func (p *Placer) Holders() map[cputopology.LCPU]uuid.UUID {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[cputopology.LCPU]uuid.UUID{}
	for id, cs := range p.dedicated {
		for _, c := range cs {
			out[c] = id
		}
	}
	return out
}

// ErrTaken is what Claim returns when a CPU of the assignment is held.
var ErrTaken = errors.New("CPUs already held")

// Claim reserves an assignment for id if every CPU it occupies is free, in one
// step: a check made apart from the reservation can be overtaken by another
// workload's placement in between.
func (p *Placer) Claim(id uuid.UUID, a *Assignment) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.dedicated[id]; ok {
		return fmt.Errorf("claim %s: already holds CPUs", id)
	}
	cpus := a.CPUs()
	for _, c := range cpus {
		if holder, held := p.holderOf(c); held {
			return fmt.Errorf("%w: CPU %d is held by %s", ErrTaken, c, holder)
		}
	}
	p.dedicated[id] = cpus
	return nil
}

// holderOf reports which workload holds a CPU. Caller must hold p.mu.
func (p *Placer) holderOf(cpu cputopology.LCPU) (uuid.UUID, bool) {
	for id, cs := range p.dedicated {
		for _, c := range cs {
			if c == cpu {
				return id, true
			}
		}
	}
	return uuid.UUID{}, false
}

// coreIsPartlyReserved reports whether any sibling of a physical core falls in
// the EVE-reserved low range.
//
// Such a core is withheld whole, not per sibling. Topology placement hands out
// physical cores, and a core whose other thread runs EVE housekeeping is not a
// core the workload owns exclusively -- handing it out would give back exactly
// the SMT interference full-pcpus-only exists to remove. The cost is that
// reserving N logical CPUs can withhold up to N whole cores (2N logical CPUs on
// an SMT host), because the low CPU numbers Linux assigns usually land on
// distinct cores. Operators sizing eve_max_vcpus must account for that; the
// Insufficient message spells it out when it bites.
func (p *Placer) coreIsPartlyReserved(pc *cputopology.PhysicalCore) bool {
	for _, s := range pc.Siblings {
		if uint32(s) < p.numReservedForEVE {
			return true
		}
	}
	return false
}

// coreIsDedicated reports whether any sibling of a physical core is already
// held by some workload.
func coreIsDedicated(pc *cputopology.PhysicalCore, dedicated map[cputopology.LCPU]bool) bool {
	for _, s := range pc.Siblings {
		if dedicated[s] {
			return true
		}
	}
	return false
}

// dedicatedLookup returns a membership set of all dedicated LCPUs.
func (p *Placer) dedicatedLookup() map[cputopology.LCPU]bool {
	m := map[cputopology.LCPU]bool{}
	for _, cs := range p.dedicated {
		for _, c := range cs {
			m[c] = true
		}
	}
	return m
}

// allocateShared places a thread-granular request (DEDICATED without
// full_pcpus_only) on the lowest-numbered free logical CPUs, one per vCPU,
// outside the EVE-reserved range. Caller must hold p.mu.
func (p *Placer) allocateShared(r Request) Result {
	ded := p.dedicatedLookup()
	avoid := lcpuSet(r.Avoid)
	available := func(c cputopology.LCPU) bool {
		return uint32(c) >= p.numReservedForEVE && !ded[c]
	}
	// Kernel-isolated CPUs are withheld: there is no thread-granular way to ask
	// for isolation, so a workload arriving here never asked, and taking one
	// would spend the operator's isolation on a workload that does not want it.
	// So is the other thread of a core only partly isolated, as for a whole-core
	// request: a core is isolated whole or serves no placement at all.
	var picked, skippedIsolated, skippedSiblings, skippedPlanned []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		if !available(c) {
			continue
		}
		if p.isolated[c] {
			skippedIsolated = append(skippedIsolated, c)
			continue
		}
		if p.coreTouchesIsolated(p.topo.ByLCPU[c]) {
			skippedSiblings = append(skippedSiblings, c)
			continue
		}
		if avoid[c] {
			skippedPlanned = append(skippedPlanned, c)
			continue
		}
		picked = append(picked, c)
		if len(picked) == r.NumVCPUs {
			break
		}
	}
	if len(picked) < r.NumVCPUs {
		return Result{Status: Insufficient, Message: fmt.Sprintf("need %d free CPUs, have %d%s",
			r.NumVCPUs, len(picked), sharedShortageClause(skippedIsolated, skippedSiblings, skippedPlanned))}
	}
	p.dedicated[r.UUID] = picked
	return Result{Status: Success, Assignment: &Assignment{OrderedHostCPUs: picked}}
}

// freeCPUs returns every logical CPU no workload holds, the EVE-reserved range
// and kernel-isolated CPUs included. Caller must hold p.mu.
func (p *Placer) freeCPUs() []cputopology.LCPU {
	ded := p.dedicatedLookup()
	var out []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		if !ded[c] {
			out = append(out, c)
		}
	}
	return out
}

// HousekeepingCPUs is where every workload without CPUs of its own runs, and
// the host processes: every CPU no workload holds, the kernel-isolated ones
// left out. Placement keeps every workload that did not ask for isolation off
// those, and this set is the other half of that: a cpuset spanning them would
// put the shared workloads and EVE's threads on exactly the CPUs the operator
// carved out, and the kernel would honour it -- isolcpus keeps the load
// balancer away, it does not refuse an explicit affinity.
//
// When the isolated set swallows every free CPU, the set is returned with them
// and isolatedOnly is true. That is a mistaken isolcpus rather than a runtime
// state, and an empty cpuset would take down every shared workload -- including,
// on a device managed through one, the path to fixing it.
func (p *Placer) HousekeepingCPUs() (cpus []cputopology.LCPU, isolatedOnly bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	free := p.freeCPUs()
	for _, c := range free {
		if !p.isolated[c] {
			cpus = append(cpus, c)
		}
	}
	if len(cpus) == 0 && len(free) > 0 {
		return free, true
	}
	return cpus, false
}

// ReservedCPUs is the low range of logical CPUs withheld from every workload,
// where EVE's own services run, the kernel-isolated ones left out: an isolcpus
// covering the reserved range is a mistake EVE warns about, not a reason to put
// threads on an isolated CPU. No workload is ever given one of these, so a set
// drawn from them cannot be taken away by a later placement.
func (p *Placer) ReservedCPUs() []cputopology.LCPU {
	var out []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		if uint32(c) < p.numReservedForEVE && !p.isolated[c] {
			out = append(out, c)
		}
	}
	return out
}

// lcpuSet is a membership set of the given CPUs.
func lcpuSet(cpus []cputopology.LCPU) map[cputopology.LCPU]bool {
	set := make(map[cputopology.LCPU]bool, len(cpus))
	for _, c := range cpus {
		set[c] = true
	}
	return set
}

// coreTouches reports whether any sibling of a core is in set.
func coreTouches(pc *cputopology.PhysicalCore, set map[cputopology.LCPU]bool) bool {
	for _, s := range pc.Siblings {
		if set[s] {
			return true
		}
	}
	return false
}

// allLCPUsSorted returns every logical CPU in the topology, ascending.
// Caller must hold p.mu.
func (p *Placer) allLCPUsSorted() []cputopology.LCPU {
	var all []cputopology.LCPU
	for i := range p.topo.Cores {
		all = append(all, p.topo.Cores[i].Siblings...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return all
}

// Allocate performs topology-aware placement for one VM. On Success it commits
// the allocation into the placer's bookkeeping -- the returned CPUs (vCPU and
// parked alike) are held by r.UUID until Free -- so a caller that then discards
// the Result must Free it. Every other status leaves the placer untouched.
func (p *Placer) Allocate(r Request) Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.dedicated[r.UUID]; ok {
		return Result{Status: InvalidRequest, Message: fmt.Sprintf("already allocated for %s", r.UUID)}
	}
	if r.NumVCPUs <= 0 {
		return Result{Status: InvalidRequest, Message: "NumVCPUs must be > 0"}
	}
	if p.degraded {
		return Result{Status: InvalidRequest, TopologyUnsupported: true,
			Message: "this node's CPU topology could not be read, so it gives no " +
				"workload CPUs of its own"}
	}

	var coresNeeded, threads int
	switch r.Mode {
	case ModeShared:
		return p.allocateShared(r)
	case ModeWholeCoreSMT:
		if r.NumVCPUs%2 != 0 {
			return Result{Status: InvalidRequest, Message: "whole-core-smt requires an even vCPU count"}
		}
		coresNeeded = r.NumVCPUs / 2
		threads = 2
	case ModeOnePerCore:
		coresNeeded = r.NumVCPUs
		threads = 1
	default:
		return Result{Status: InvalidRequest, Message: fmt.Sprintf("unknown placement mode %v", r.Mode)}
	}

	// A whole-core-SMT request on a node where no core has the required thread
	// count is unsatisfiable, not short of capacity: the loop below would skip
	// every core and report a shortage of cores that could never help. Separating
	// the two matters because the shortage advice -- stop a workload, add cores --
	// is false on an SMT-disabled or non-SMT host, which is the common case on
	// ARM64 and the most likely way the default policy fails.
	if r.Mode == ModeWholeCoreSMT && !p.anyCoreHasThreads(threads) {
		return Result{
			Status:              InvalidRequest,
			TopologyUnsupported: true,
			Message:             topologyUnsupportedMessage(p.topo, threads),
		}
	}

	dedicated := p.dedicatedLookup()
	avoid := lcpuSet(r.Avoid)

	// Free cores grouped by NUMA node, preserving deterministic order. Cores
	// skipped for a structural reason are counted so a shortage can say why:
	// a bare "insufficient" on a host with visibly idle CPUs is unactionable.
	freeByNUMA := map[uint][]*cputopology.PhysicalCore{}
	numaOrder := []uint{}
	var counts skipCounts
	totalFree := 0
	for i := range p.topo.Cores {
		pc := &p.topo.Cores[i]
		// Isolation is tested first: it decides which cores the request may
		// have at all, so every count below is of cores it could otherwise
		// have used, and a shortage names what actually stands in the way.
		if r.RequireIsolated {
			// Only a wholly isolated core will do: a workload that asked for
			// isolation and got a core whose sibling the kernel still schedules
			// on has not been isolated from anything.
			if !p.coreIsIsolated(pc) {
				if p.coreTouchesIsolated(pc) {
					counts.halfIsolated++
				}
				continue
			}
		} else if p.coreTouchesIsolated(pc) {
			counts.isolatedReserved++
			continue
		}
		if p.coreIsPartlyReserved(pc) {
			counts.partlyReserved++
			continue
		}
		if coreIsDedicated(pc, dedicated) {
			counts.held++
			continue
		}
		if coreTouches(pc, avoid) {
			counts.planned++
			continue
		}
		// whole-core-smt maps one vCPU onto each SMT sibling, so it can only use
		// a core with exactly that many threads. On hybrid parts a single-threaded
		// core (e.g. an E-core) cannot present threads=2; skip it here rather than
		// emit an assignment with fewer host CPUs than vCPUs.
		if r.Mode == ModeWholeCoreSMT && len(pc.Siblings) != threads {
			counts.notSMT++
			continue
		}
		if _, ok := freeByNUMA[pc.NUMA]; !ok {
			numaOrder = append(numaOrder, pc.NUMA)
		}
		freeByNUMA[pc.NUMA] = append(freeByNUMA[pc.NUMA], pc)
		totalFree++
	}
	sort.Slice(numaOrder, func(i, j int) bool { return numaOrder[i] < numaOrder[j] })

	if totalFree < coresNeeded {
		return Result{
			Status:      Insufficient,
			Message:     shortageMessage(coresNeeded, totalFree, threads, r.RequireIsolated, counts),
			CoresNeeded: coresNeeded,
			CoresFree:   totalFree,
		}
	}

	// allNodes may assume sufficiency: total free is already >= coresNeeded.
	singleNode := func() []*cputopology.PhysicalCore {
		for _, n := range numaOrder {
			if cand := freeByNUMA[n]; len(cand) >= coresNeeded {
				return pickCores(cand, coresNeeded)
			}
		}
		return nil
	}
	allNodes := func() []*cputopology.PhysicalCore {
		var all []*cputopology.PhysicalCore
		for _, n := range numaOrder {
			all = append(all, freeByNUMA[n]...)
		}
		return pickCores(all, coresNeeded)
	}
	// fewestNodes spans as few nodes as can hold the request: the nodes with
	// the most free cores first, the lower-numbered on a tie.
	fewestNodes := func() []*cputopology.PhysicalCore {
		byFree := append([]uint(nil), numaOrder...)
		sort.SliceStable(byFree, func(i, j int) bool {
			return len(freeByNUMA[byFree[i]]) > len(freeByNUMA[byFree[j]])
		})
		var all []*cputopology.PhysicalCore
		for _, n := range byFree {
			all = append(all, freeByNUMA[n]...)
		}
		return pickCores(all, coresNeeded)
	}

	var chosen []*cputopology.PhysicalCore
	switch r.NUMA {
	case NUMALocal:
		if chosen = singleNode(); chosen == nil {
			return Result{
				Status: NeedsRebalance,
				Message: fmt.Sprintf("need %d cores in one NUMA node; none has enough (total free %d)",
					coresNeeded, totalFree),
				CoresNeeded: coresNeeded,
				CoresFree:   totalFree,
			}
		}
	case NUMABestEffort:
		if chosen = singleNode(); chosen == nil {
			chosen = fewestNodes()
		}
	default: // NUMAAllowCross: no NUMA consideration at all
		chosen = allNodes()
	}

	var ordered, parked []cputopology.LCPU
	nodeSet := map[uint]bool{}
	for _, pc := range chosen {
		nodeSet[pc.NUMA] = true
		switch r.Mode {
		case ModeWholeCoreSMT:
			ordered = append(ordered, pc.Siblings...)
		case ModeOnePerCore:
			ordered = append(ordered, pc.Siblings[0])
			if len(pc.Siblings) > 1 {
				parked = append(parked, pc.Siblings[1:]...)
			}
		}
	}

	nodes := make([]uint, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })

	assignment := &Assignment{
		OrderedHostCPUs: ordered,
		Guest:           GuestTopology{Sockets: 1, Cores: coresNeeded, Threads: threads},
		ParkedCPUs:      parked,
		NUMANodes:       nodes,
	}
	if err := assignment.validate(p.topo); err != nil {
		return Result{
			Status:  InvalidRequest,
			Message: fmt.Sprintf("internal error: computed placement is inconsistent: %v", err),
		}
	}

	p.dedicated[r.UUID] = append(append([]cputopology.LCPU{}, ordered...), parked...)
	return Result{Status: Success, Assignment: assignment}
}

// validate checks a computed assignment for internal consistency before it is
// handed out. The guest -smp topology and the host CPU list are two views of one
// decision, and nothing downstream cross-checks them: today a mismatch surfaces
// only when QEMU refuses the vCPU count, i.e. as a failed domain start with no
// indication of which side was wrong.
//
// The topology is a parameter because NUMANodes cannot be verified from the
// assignment alone -- it is a property of the host CPUs that were picked.
func (a *Assignment) validate(topo *cputopology.Topology) error {
	if want := a.Guest.Sockets * a.Guest.Cores * a.Guest.Threads; want != len(a.OrderedHostCPUs) {
		return fmt.Errorf("guest topology %d/%d/%d needs %d vCPUs but %d host CPUs were assigned",
			a.Guest.Sockets, a.Guest.Cores, a.Guest.Threads, want, len(a.OrderedHostCPUs))
	}
	vcpus := make(map[cputopology.LCPU]bool, len(a.OrderedHostCPUs))
	nodes := map[uint]bool{}
	for _, c := range a.OrderedHostCPUs {
		if vcpus[c] {
			return fmt.Errorf("host CPU %d is assigned to more than one vCPU", c)
		}
		vcpus[c] = true
		pc, ok := topo.ByLCPU[c]
		if !ok {
			return fmt.Errorf("host CPU %d is not in the host topology", c)
		}
		nodes[pc.NUMA] = true
	}
	for _, c := range a.ParkedCPUs {
		if vcpus[c] {
			return fmt.Errorf("host CPU %d is both a vCPU and parked", c)
		}
	}
	if len(a.NUMANodes) != len(nodes) {
		return fmt.Errorf("NUMANodes %v does not match the nodes of the assigned CPUs", a.NUMANodes)
	}
	for _, n := range a.NUMANodes {
		if !nodes[n] {
			return fmt.Errorf("NUMANodes %v does not match the nodes of the assigned CPUs", a.NUMANodes)
		}
	}
	return nil
}

// anyCoreHasThreads reports whether the topology has at least one physical core
// presenting exactly n hardware threads, regardless of whether it is free.
func (p *Placer) anyCoreHasThreads(n int) bool {
	for i := range p.topo.Cores {
		if len(p.topo.Cores[i].Siblings) == n {
			return true
		}
	}
	return false
}

// topologyUnsupportedMessage explains why no arrangement of this node's CPUs can
// present the requested thread count, naming the thread counts it does have so
// the operator can tell an SMT-less machine from a misconfigured one.
func topologyUnsupportedMessage(topo *cputopology.Topology, threads int) string {
	counts := map[int]bool{}
	for i := range topo.Cores {
		counts[len(topo.Cores[i].Siblings)] = true
	}
	have := make([]int, 0, len(counts))
	for n := range counts {
		have = append(have, n)
	}
	sort.Ints(have)

	detail := fmt.Sprintf("every core has %s", threadCountPhrase(have))
	if len(have) == 1 && have[0] == 1 {
		detail = "no core has an SMT sibling (SMT is disabled or the CPU has none)"
	}
	return fmt.Sprintf("whole-core-smt needs a physical core with %d hardware threads, but %s: "+
		"threads=%d cannot be presented in any arrangement, so freeing CPUs will not help",
		threads, detail, threads)
}

// threadCountPhrase renders the thread counts a node's cores have, e.g.
// "1 thread" or "1 or 4 threads".
func threadCountPhrase(counts []int) string {
	if len(counts) == 1 && counts[0] == 1 {
		return "1 thread"
	}
	parts := make([]string, 0, len(counts))
	for _, n := range counts {
		parts = append(parts, fmt.Sprint(n))
	}
	return strings.Join(parts, " or ") + " threads"
}

// skipCounts counts the cores a whole-core request passed over, by reason, so a
// shortage can say why. Allocate tests isolation first: for a request for
// isolation every other count is of wholly isolated cores, and for any other
// request it is of cores with no isolated sibling.
type skipCounts struct {
	// isolatedReserved: kernel-isolated cores withheld from an ordinary request.
	isolatedReserved int
	// halfIsolated: cores some but not all of whose threads are isolated, which
	// a request for isolation cannot use.
	halfIsolated int
	// partlyReserved: cores with a thread in the range reserved for EVE.
	partlyReserved int
	// held: cores another workload holds.
	held int
	// planned: free cores the plan sets aside for workloads not started yet.
	planned int
	// notSMT: cores without the thread count a whole-core-smt request needs.
	notSMT int
}

// shortageMessage explains a core shortage, naming the structural reasons that
// removed cores from the pool. Without them the operator sees idle CPUs in top
// and an "insufficient" from EVE, and has no way to connect the two.
func shortageMessage(needed, free, threads int, isolated bool, c skipCounts) string {
	kind := "free cores"
	if isolated {
		kind = "free kernel-isolated cores"
	}
	msg := fmt.Sprintf("need %d %s, have %d", needed, kind, free)
	var because []string
	if c.held > 0 {
		because = append(because, fmt.Sprintf("%d are held by other workloads", c.held))
	}
	if c.planned > 0 {
		because = append(because, fmt.Sprintf("%d are planned for workloads not "+
			"started yet", c.planned))
	}
	if c.isolatedReserved > 0 {
		// Without this the operator sees idle CPUs and an "insufficient", and
		// nothing connects the two: the cores are free, they are simply not on
		// offer to a workload that did not ask for isolation.
		because = append(because, fmt.Sprintf(
			"%d cores are kernel-isolated (isolcpus) and are held for workloads "+
				"that request isolation", c.isolatedReserved))
	}
	if c.halfIsolated > 0 {
		because = append(because, fmt.Sprintf(
			"%d cores are only partly kernel-isolated: isolcpus leaves out an SMT "+
				"sibling, and the kernel still schedules on it", c.halfIsolated))
	}
	if c.partlyReserved > 0 {
		because = append(because, fmt.Sprintf(
			"%d cores are partly reserved for EVE and cannot be handed out whole",
			c.partlyReserved))
	}
	if c.notSMT > 0 {
		// Not "have no SMT sibling": a core is skipped whenever its thread count
		// differs from the request, which includes 4-thread cores that do have
		// siblings.
		because = append(because, fmt.Sprintf(
			"%d cores do not have exactly %d hardware threads and cannot present threads=%d",
			c.notSMT, threads, threads))
	}
	if len(because) > 0 {
		msg += " (" + strings.Join(because, "; ") + ")"
	}
	return msg
}

// sharedShortageClause names the free CPUs a thread-granular shortage passed
// over -- the kernel-isolated ones, the other threads of cores only partly
// isolated, and those planned for workloads not started yet -- so the operator
// is not left comparing an "insufficient" against CPUs that look idle.
func sharedShortageClause(isolated, siblings, planned []cputopology.LCPU) string {
	var because []string
	if len(isolated) > 0 {
		because = append(because, fmt.Sprintf("CPUs %v are kernel-isolated and are "+
			"held for workloads that request isolation", isolated))
	}
	if len(siblings) > 0 {
		because = append(because, fmt.Sprintf("CPUs %v share a core with a "+
			"kernel-isolated CPU and serve no placement", siblings))
	}
	if len(planned) > 0 {
		because = append(because, fmt.Sprintf("CPUs %v are planned for workloads "+
			"not started yet", planned))
	}
	if len(because) == 0 {
		return ""
	}
	return " (" + strings.Join(because, "; ") + ")"
}

// pickCores returns the first n cores from an already-deterministic slice.
func pickCores(cores []*cputopology.PhysicalCore, n int) []*cputopology.PhysicalCore {
	out := make([]*cputopology.PhysicalCore, n)
	copy(out, cores[:n])
	return out
}
