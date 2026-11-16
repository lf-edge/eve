// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// A repack moves running workloads so that one which cannot be placed well
// can be. The device owns the plan, so it is the one that says who has to move;
// the controller restarts exactly the workloads the device flags, all at once,
// and the device takes it from there.
//
// Two kinds of workload take part. A beneficiary is the reason for the repack:
// it was refused as needing a repack, or it runs on a placement a repack would
// improve. A member is placed perfectly well itself, but stands on CPUs the
// plan gives to someone in the set -- B is not placed badly, it is in A's way
// -- so it carries RepackFor instead of a worse verdict.

// unplacedHolders returns the running workloads the plan does not place, in a
// stable order, leaving out those on their way off their CPUs (goingDown),
// which the plan rightly no longer counts. A repack restarts workloads onto
// their planned slots, so a plan that leaves out a running workload is an
// eviction, not a repack: with the isolated pool full, a third isolated
// workload is "planned" only by dropping one of the two running, and
// restarting them helps nobody.
func unplacedHolders(holders map[cputopology.LCPU]uuid.UUID,
	plan map[uuid.UUID]cpuallocator.Result, goingDown func(uuid.UUID) bool) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, id := range holders {
		if !seen[id] && !plannedOK(plan, id) && !goingDown(id) {
			out = append(out, id)
		}
		seen[id] = true
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// repackMembers returns the running workloads that have to be restarted,
// together with the beneficiaries, for every beneficiary to reach its planned
// slot: the closure over "who stands on a CPU someone in the set is planned
// onto". Planned slots are disjoint, so once the whole set has released its
// CPUs each member finds its own slot free. Beneficiaries are never members.
func repackMembers(holders map[cputopology.LCPU]uuid.UUID,
	plan map[uuid.UUID]cpuallocator.Result,
	beneficiaries map[uuid.UUID]bool) map[uuid.UUID]bool {
	members := map[uuid.UUID]bool{}
	visited := map[uuid.UUID]bool{}
	var queue []uuid.UUID
	for id := range beneficiaries {
		visited[id] = true
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if !plannedOK(plan, id) {
			continue
		}
		for _, cpu := range plan[id].Assignment.CPUs() {
			holder, held := holders[cpu]
			if !held || visited[holder] {
				continue
			}
			visited[holder] = true
			members[holder] = true
			queue = append(queue, holder)
		}
	}
	return members
}

// placementWaiting is returned instead of a placement error when a workload's
// planned CPUs are held only by workloads on their way off them.
type placementWaiting struct {
	holders []string
	// appSet: waiting for the complete demand set, not for holders.
	appSet bool
}

func (w *placementWaiting) Error() string {
	if w.appSet {
		return "waiting for the set of applications this node runs"
	}
	return fmt.Sprintf("waiting for %s to release the planned CPUs",
		strings.Join(w.holders, ", "))
}

// refreshPlacement brings one workload in line with the placement state: a
// shared workload's cpuset follows the housekeeping set, and so do the IO
// threads of one under io_placement=housekeeping; a waiting workload retries
// its placement, and a running one learns whether a repack needs it to move. It runs in the workload's own handler, on every CPU-change wakeup and
// every tick, and derives all of it from the state as it stands, so a wakeup
// that is missed or overtaken costs a tick's delay, never a wrong outcome.
func refreshPlacement(ctx *domainContext, key string) {
	if !ctx.cpuPinningSupported {
		return
	}
	status := lookupDomainStatus(ctx, key)
	config := lookupDomainConfig(ctx, key)
	if status == nil || config == nil || crashFrozen(status) {
		return
	}
	if status.Placement.Wait.Waiting() {
		if config.Activate && !status.Activated && !status.HasError() &&
			status.State != types.BROKEN {
			updateStatusFromConfig(status, *config)
			doActivate(ctx, *config, status)
			publishDomainStatus(ctx, status)
			return
		}
		status.Placement.Wait = types.CPUWait{}
		publishDomainStatus(ctx, status)
	}
	if !status.Activated {
		return
	}
	changed := false
	var repackFor []string
	if assigned := status.Placement.Assigned; assigned.Holds() {
		repackFor = ctx.cpuPlacement.repackFor(ctx, status.UUIDandVersion.UUID)
		if len(assigned.IOCPUs) > 0 {
			if hk := ctx.cpuPlacement.housekeeping(); !slices.Equal(hk, assigned.IOCPUs) {
				changed = setIOCPUs(config, status, hk)
			}
		}
	} else if hk := ctx.cpuPlacement.housekeeping(); !slices.Equal(hk, status.VmConfig.CPUs) {
		changed = setSharedCPUs(config, status, hk)
	}
	if !slices.Equal(status.Placement.RepackFor, repackFor) {
		if len(repackFor) > 0 {
			log.Noticef("CPU placement: %s holds CPUs the plan gives to %s; it has "+
				"to be restarted together with them for a repack",
				status.DisplayName, strings.Join(repackFor, ", "))
		} else {
			log.Noticef("CPU placement: %s is no longer part of a repack",
				status.DisplayName)
		}
		status.Placement.RepackFor = repackFor
		changed = true
	}
	if changed {
		publishDomainStatus(ctx, status)
	}
}
