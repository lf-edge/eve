// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
)

// cpuPlacement is domainmgr's CPU placement state.
//
// Every placement decision and every change to the placer is made under its
// mutex, so a decision sees one consistent snapshot. A change is announced once
// it is visible: the derived view is dropped, the reports derived from the
// placer are republished, and every domain handler is woken to bring its
// workload in line (refreshPlacement). Nothing depends on the order events
// arrive in: a decision reads each input -- the placer, the planned set, the
// repack flags -- as it stands, and a handler that misses a wakeup catches up
// on its next tick.
type cpuPlacement struct {
	mu     sync.Mutex
	placer *cpuallocator.Placer
	// isolationWarnings are the mistakes in the node's isolcpus, reported on the
	// isolated pool. isolcpus changes only across a reboot.
	isolationWarnings []types.CPUPoolWarning
	// wantsRepack holds the workloads a repack would be for: refused as
	// needing one, or running on a placement worse than planned. A flag
	// outlives the workload's restart, which is part of the repack; it ends
	// when the workload is placed as planned, is refused for another reason,
	// is stopped, or is deleted.
	wantsRepack map[uuid.UUID]bool
	// view is derived from the inputs; nil when one changed since.
	view *placementView
}

// placementView is what placement derives from its inputs at one moment.
type placementView struct {
	intents map[uuid.UUID]cpuIntent
	plan    map[uuid.UUID]cpuallocator.Result
	holders map[cputopology.LCPU]uuid.UUID
	// unplaced are the running workloads the plan leaves out (unplacedHolders).
	unplaced []uuid.UUID
	// beneficiaries are the flagged workloads the plan can place.
	beneficiaries map[uuid.UUID]bool
	// members maps each running workload that has to move for a repack to the
	// names of the beneficiaries it moves for.
	members map[uuid.UUID][]string
}

func newCPUPlacement(placer *cpuallocator.Placer) *cpuPlacement {
	return &cpuPlacement{
		placer:            placer,
		isolationWarnings: isolationWarnings(placer, time.Now()),
		wantsRepack:       map[uuid.UUID]bool{},
	}
}

// viewLocked returns the current view, deriving it if an input changed.
func (c *cpuPlacement) viewLocked(ctx *domainContext) *placementView {
	if c.view != nil {
		return c.view
	}
	intents := plannedIntents(ctx)
	plan := planFor(c.placer, intents)
	v := &placementView{intents: intents, plan: plan, holders: c.placer.Holders(),
		beneficiaries: map[uuid.UUID]bool{}, members: map[uuid.UUID][]string{}}
	v.unplaced = unplacedHolders(v.holders, plan, func(id uuid.UUID) bool {
		return goingDown(ctx, id)
	})
	if len(v.unplaced) == 0 {
		var names []string
		for id := range c.wantsRepack {
			if plannedOK(plan, id) {
				v.beneficiaries[id] = true
				names = append(names, v.name(id))
			}
		}
		sort.Strings(names)
		for id := range repackMembers(v.holders, plan, v.beneficiaries) {
			v.members[id] = names
		}
	}
	c.view = v
	return v
}

// name names a workload for a message, falling back to its UUID.
func (v *placementView) name(id uuid.UUID) string {
	if intent, ok := v.intents[id]; ok && intent.displayName != "" {
		return intent.displayName
	}
	return id.String()
}

// changedLocked announces a change to a placement input.
func (c *cpuPlacement) changedLocked(ctx *domainContext) {
	c.view = nil
	c.publishLocked(ctx)
	notifyCPUHandlers()
}

// inputsChanged announces a change to the planned set (demand set,
// DomainConfigs), which is made outside placement.
func (c *cpuPlacement) inputsChanged(ctx *domainContext) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.changedLocked(ctx)
}

// publish republishes everything derived from the placer and the plan.
func (c *cpuPlacement) publish(ctx *domainContext) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.publishLocked(ctx)
}

// publishLocked brings the pool report and the plan mirror in line with the
// placer and the plan.
func (c *cpuPlacement) publishLocked(ctx *domainContext) {
	hk, isolatedOnly := c.placer.HousekeepingCPUs()
	if isolatedOnly {
		log.Errorf("CPU isolation: every free CPU (%v) is kernel-isolated, so the "+
			"housekeeping set would be empty; using it anyway. Narrow isolcpus on "+
			"the kernel command line.", hk)
	}
	status := cpuPoolStatus(c.placer, c.isolationWarnings)
	if err := ctx.pubCPUPoolStatus.Publish(status.Key(), status); err != nil {
		log.Errorf("CPU pool report: publish failed: %v", err)
	}
	publishCPUPlan(c.viewLocked(ctx))
}

// housekeeping is the CPU set every workload without CPUs of its own runs on,
// and the emulator and IO threads of one under io_placement=housekeeping.
func (c *cpuPlacement) housekeeping() []uint32 {
	hk, _ := c.placer.HousekeepingCPUs()
	return cpuallocator.LCPUsToUint32(hk)
}

// followHousekeeping brings what a workload shares in line with the
// housekeeping set as it stands, in its status only: every CPU of a workload
// without CPUs of its own, and the IO CPUs of one under
// io_placement=housekeeping. It is for a domain about to start again, whose
// cgroup the start creates from its status; refreshPlacement keeps a running
// domain in line.
func (c *cpuPlacement) followHousekeeping(status *types.DomainStatus) {
	hk := c.housekeeping()
	switch a := status.Placement.Assigned; {
	case !a.Holds():
		status.VmConfig.CPUs = hk
	case len(a.IOCPUs) > 0:
		a.IOCPUs = hk
		status.Placement.Assigned = a
		status.VmConfig.CPUs = a.DomainCPUs()
	}
}

// assign gives a workload the CPUs its policy asks for, or says why it cannot
// have them: a refusal (a placementError) or a wait for planned CPUs on their
// way back (a placementWaiting). It is the one place a placement is decided.
func (c *cpuPlacement) assign(ctx *domainContext, config *types.DomainConfig,
	status *types.DomainStatus) error {
	intent := intentOfConfig(config)
	placement, err := intent.placement()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id := intent.id
	held := c.placer.Holds(id)
	// CPUs held from a doActivate that returned early (EVE-k leaving the VM to
	// the cluster) are kept.
	if intent.ownsCPUs() && held && status.Placement.Assigned.Holds() {
		return nil
	}
	c.placer.Free(id)
	clearCPUs(status)
	if !intent.ownsCPUs() {
		status.VmConfig.CPUs = c.housekeeping()
		if held {
			c.changedLocked(ctx)
		}
		return nil
	}
	// Planned against part of the set, a workload takes CPUs the full plan
	// gives to another: right after a boot the demand set can still be partial.
	if !demandSetComplete(ctx) {
		return &placementWaiting{appSet: true}
	}

	wanted := c.wantsRepack[id]
	err = c.placeLocked(ctx, intent, placement, status)
	var waiting *placementWaiting
	var refusal *placementError
	switch {
	case err == nil:
		c.setWantsRepack(id, status.Placement.Verdict == types.CPUPlacementPlacedSuboptimal)
	case errors.As(err, &waiting):
	case errors.As(err, &refusal):
		c.setWantsRepack(id, refusal.Status == types.CPUPlacementNeedsRepack)
	}
	if err == nil || held || wanted != c.wantsRepack[id] {
		c.changedLocked(ctx)
	}
	return err
}

func (c *cpuPlacement) setWantsRepack(id uuid.UUID, wants bool) {
	if wants {
		c.wantsRepack[id] = true
	} else {
		delete(c.wantsRepack, id)
	}
}

// placeLocked decides one placement. Caller holds c.mu.
func (c *cpuPlacement) placeLocked(ctx *domainContext, intent cpuIntent,
	placement resolvedPlacement, status *types.DomainStatus) error {
	if err := validateVCPUCount(placement, intent.vcpus); err != nil {
		return err
	}
	if placement.Mode != cpuallocator.ModeShared && !ctx.cpuTopologyPinningSupported {
		return placementErrorf(types.CPUPlacementTopologyUnsupported,
			"whole-core CPU placement for %s: this node cannot pin individual "+
				"vCPUs or expose a guest SMT topology", intent.displayName)
	}
	// isolcpus is a boot parameter: a node without it cannot acquire one.
	if placement.RequireIsolated && len(c.placer.IsolatedCPUs()) == 0 {
		return placementErrorf(types.CPUPlacementIsolationUnavailable,
			"isolated CPUs for %s: this node's kernel isolates no CPUs "+
				"(no isolcpus on the kernel command line)", intent.displayName)
	}
	view := c.viewLocked(ctx)
	planned := view.plan[intent.id]
	verdict := types.CPUPlacementPlaced
	var a *cpuallocator.Assignment
	if plannedOK(view.plan, intent.id) {
		holders := holdersOf(c.placer.Holders(), planned.Assignment)
		if len(holders) == 0 {
			a = planned.Assignment
		} else if w := c.waitForSlotLocked(ctx, view, holders); w != nil {
			return w
		}
	}
	if a == nil {
		// The planned CPUs are held by workloads staying where they are, so
		// this one is placed among the free CPUs, off those the plan sets aside
		// for workloads not started yet.
		notStarted := func(id uuid.UUID) bool {
			return id != intent.id && !c.placer.Holds(id)
		}
		res := c.placer.Propose(placement.request(intent,
			plannedCPUs(view.plan, notStarted)))
		if res.Status != cpuallocator.Success {
			return c.refusalLocked(view, intent, res)
		}
		a = res.Assignment
		// Only a whole-core placement is judged against the plan.
		if placement.Mode != cpuallocator.ModeShared && plannedOK(view.plan, intent.id) &&
			c.placer.Score(a).WorseThan(c.placer.Score(planned.Assignment)) {
			verdict = types.CPUPlacementPlacedSuboptimal
			log.Warnf("CPU placement: %s placed on %v, worse than its planned %v; "+
				"a repack of the running workloads would reach the plan",
				intent.displayName, a.OrderedHostCPUs, planned.Assignment.OrderedHostCPUs)
		}
	}
	// Placement runs under c.mu, so nothing has claimed a CPU since the
	// assignment was chosen; a failure here is a fault in EVE.
	if err := c.placer.Claim(intent.id, a); err != nil {
		return internalPlacementError(intent.displayName, err)
	}
	// Under io_placement=housekeeping the emulator and IO threads run on the
	// housekeeping set as it stands now that the workload holds its own CPUs,
	// and follow it (refreshPlacement). It always holds the CPUs reserved for
	// EVE, which no workload is given.
	var ioCPUs []uint32
	if placement.IOHousekeeping {
		ioCPUs = c.housekeeping()
	}
	applyAssignment(status, a, ioCPUs, verdict, intent.policy.Pinned)
	assigned := status.Placement.Assigned
	log.Noticef("CPU placement: %s on host CPUs %v (parked %v, IO %v), guest "+
		"topology %d/%d/%d", intent.displayName, assigned.CPUs, assigned.ParkedCPUs,
		assigned.IOCPUs, a.Guest.Sockets, a.Guest.Cores, a.Guest.Threads)
	return nil
}

// refusalLocked classifies a failed placement against the plan. Caller holds
// c.mu.
func (c *cpuPlacement) refusalLocked(view *placementView, intent cpuIntent,
	res cpuallocator.Result) *placementError {
	var blockers, unplaced []string
	if plannedOK(view.plan, intent.id) {
		for _, holder := range holdersOf(view.holders, view.plan[intent.id].Assignment) {
			blockers = append(blockers, view.name(holder))
		}
	}
	for _, id := range view.unplaced {
		unplaced = append(unplaced, view.name(id))
	}
	sort.Strings(blockers)
	err := liveAllocationError(intent.displayName, intent.id, res, view.plan,
		blockers, unplaced)
	if res.Status == cpuallocator.TopologyUnsupported && c.placer.Degraded() {
		return err.retryWhen("Deploy the workload on a node whose CPU topology "+
			"EVE can read, or set cpu_policy=housekeeping for it.%s", noAutoRetry)
	}
	return err
}

// waitForSlotLocked decides whether a workload whose planned CPUs are held, by
// holders, waits for them: when every holder is on its way off them --
// stopping, gone, or flagged to move in a repack, which the controller
// restarts as one set. The wait lasts only while that holds (refreshPlacement
// retries on every change and tick), so it needs no timeout. Caller holds c.mu.
func (c *cpuPlacement) waitForSlotLocked(ctx *domainContext, view *placementView,
	holders []uuid.UUID) *placementWaiting {
	var names []string
	for _, h := range holders {
		if !goingDown(ctx, h) && !view.beneficiaries[h] && view.members[h] == nil {
			return nil
		}
		names = append(names, view.name(h))
	}
	sort.Strings(names)
	return &placementWaiting{holders: names}
}

// goingDown reports whether a workload holding CPUs is on its way off them: its
// DomainConfig is gone or no longer asks for activation, so it releases them
// once it has stopped.
func goingDown(ctx *domainContext, id uuid.UUID) bool {
	config := lookupDomainConfig(ctx, id.String())
	return config == nil || !config.Activate
}

// release gives back the CPUs a workload holds and clears them from its status.
func (c *cpuPlacement) release(ctx *domainContext, status *types.DomainStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := status.UUIDandVersion.UUID
	held := c.placer.Holds(id)
	c.placer.Free(id)
	clearCPUs(status)
	if held {
		c.changedLocked(ctx)
	}
}

// forget ends a workload's repack flag, when it is stopped or deleted.
func (c *cpuPlacement) forget(ctx *domainContext, id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wantsRepack[id] {
		delete(c.wantsRepack, id)
		c.changedLocked(ctx)
	}
}

// reseed records what the workloads still running hold, from the DomainStatus
// objects that survived a domainmgr restart in /run: a placer created fresh
// would otherwise hand their CPUs to another workload.
func (c *cpuPlacement) reseed(ctx *domainContext) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx.pubDomainStatus.Iterate(func(_ string, item interface{}) bool {
		status := item.(types.DomainStatus)
		id := status.UUIDandVersion.UUID
		if status.Placement.Verdict == types.CPUPlacementPlacedSuboptimal ||
			status.Placement.Verdict == types.CPUPlacementNeedsRepack {
			c.wantsRepack[id] = true
		}
		assigned := status.Placement.Assigned
		if !assigned.Holds() {
			return true
		}
		a := &cpuallocator.Assignment{
			OrderedHostCPUs: uint32sToLCPUs(assigned.CPUs),
			ParkedCPUs:      uint32sToLCPUs(assigned.ParkedCPUs),
			Guest:           assigned.Guest,
		}
		// Two statuses claiming one CPU cannot come from any sequence of
		// placements; the first keeps the CPU rather than both holding it.
		if err := c.placer.Claim(id, a); err != nil {
			log.Errorf("CPU placement: cannot reseed %s with CPUs %v: %v",
				status.DisplayName, a.CPUs(), err)
			return true
		}
		log.Noticef("CPU placement: reseeded %s with CPUs %v after a domainmgr restart",
			status.DisplayName, a.CPUs())
		return true
	})
	c.view = nil
}

// repackFor returns the beneficiaries a workload has to move for, or nil.
func (c *cpuPlacement) repackFor(ctx *domainContext, id uuid.UUID) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.viewLocked(ctx).members[id]
}

// applyAssignment writes a placement into the status, the one place a
// workload's CPUs are set. The parked siblings stay out of VmConfig.CPUs, which
// becomes the cpuset: they are held so that nothing shares the workload's
// cores, its own emulator and IO threads included. The CPUs of a workload not
// pinned have no vCPU order to keep, and are sorted.
func applyAssignment(status *types.DomainStatus, a *cpuallocator.Assignment,
	ioCPUs []uint32, verdict types.CPUPlacementVerdict, pinned bool) {
	cpus := cpuallocator.LCPUsToUint32(a.OrderedHostCPUs)
	if !pinned {
		slices.Sort(cpus)
	}
	status.Placement.Assigned = types.CPUAssignment{
		CPUs:       cpus,
		ParkedCPUs: cpuallocator.LCPUsToUint32(a.ParkedCPUs),
		IOCPUs:     ioCPUs,
		Guest:      a.Guest,
	}
	status.VmConfig.CPUs = status.Placement.Assigned.DomainCPUs()
	status.Placement.Verdict = verdict
}

// clearCPUs resets what the workload runs on and the verdict on its placement.
func clearCPUs(status *types.DomainStatus) {
	status.VmConfig.CPUs = nil
	status.Placement.Assigned = types.CPUAssignment{}
	status.Placement.Verdict = types.CPUPlacementUnspecified
}

// holdersOf returns, in a stable order, the workloads holding any CPU of an
// assignment.
func holdersOf(holders map[cputopology.LCPU]uuid.UUID, a *cpuallocator.Assignment) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, cpu := range a.CPUs() {
		if id, held := holders[cpu]; held && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// uint32sToLCPUs converts CPU ids as statuses carry them to the topology's.
func uint32sToLCPUs(cpus []uint32) []cputopology.LCPU {
	return generics.MapList(cpus, func(cpu uint32) cputopology.LCPU {
		return cputopology.LCPU(cpu)
	})
}
