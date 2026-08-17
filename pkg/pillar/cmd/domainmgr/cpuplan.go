// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// cpuPlanFile is where the current placement plan is mirrored. It is derived
// state, recomputed from the app configs and the topology, and exists on disk
// only so an operator can see what the device decided and why a workload is
// where it is. Nothing reads it back.
var cpuPlanFile = filepath.Join(runDirname, "cpuplan.json")

// plannedPlacement is one workload's entry in the mirrored plan.
type plannedPlacement struct {
	UUID        string   `json:"uuid"`
	DisplayName string   `json:"display_name"`
	Mode        string   `json:"mode"`
	VCPUs       int      `json:"vcpus"`
	Status      string   `json:"status"`
	HostCPUs    []uint32 `json:"host_cpus,omitempty"`
	ParkedCPUs  []uint32 `json:"parked_cpus,omitempty"`
	Message     string   `json:"message,omitempty"`
}

// cpuPlan is the mirrored plan as a whole.
type cpuPlan struct {
	Comment   string             `json:"_comment"`
	Workloads []plannedPlacement `json:"workloads"`
}

// plannedIntents is the set of workloads placement is planned over: every app
// the controller intends to run on this node, whether or not it has got as far
// as a DomainConfig.
//
// It has to come from zedmanager's demand set rather than from the DomainConfigs
// received so far, because a DomainConfig is only published once the app's
// volumes are resolved and its network is up. Planning over what has arrived
// makes the layout depend on image download order: the app that finished
// downloading first is planned as if it were alone and takes CPUs the full plan
// would have given to another, so the same config lays out differently after a
// reboot.
//
// The fallback exists only so a missing pubsub message can never stop a
// workload from starting. It restores the order-dependent behaviour, which is
// why it is loud.
func plannedIntents(ctx *domainContext) []cpuIntent {
	if ctx.subCPUDemandSet != nil {
		if item, err := ctx.subCPUDemandSet.Get("global"); err == nil {
			set, ok := item.(types.CPUDemandSet)
			if ok {
				intents := make([]cpuIntent, 0, len(set.Apps))
				for _, app := range set.Apps {
					intents = append(intents, intentOfDemand(app))
				}
				return intents
			}
			log.Errorf("plannedIntents: unexpected type %T for CPUDemandSet", item)
		}
	}
	// Not an empty set: an empty one is published explicitly, and arrives as a
	// CPUDemandSet with no apps.
	log.Warnf("CPU planning: no demand set from zedmanager yet; planning over " +
		"the DomainConfigs received so far, which makes the layout depend on " +
		"the order workloads activate in")
	if ctx.subDomainConfig == nil {
		return nil
	}
	var intents []cpuIntent
	for _, item := range ctx.subDomainConfig.GetAll() {
		if config, ok := item.(types.DomainConfig); ok {
			intents = append(intents, intentOfConfig(&config))
		}
	}
	return intents
}

// planPinnedPlacement computes the placement plan for every pinned workload the
// controller has configured, whether or not it is running yet.
//
// Planning the whole set, rather than allocating for each workload as it
// activates, is what makes the outcome independent of the order workloads start
// in -- including a workload with a start delay, whose CPUs must still be
// waiting for it when it eventually starts.
//
// The plan is recomputed rather than remembered: it is a pure function of the
// configured set and the topology, so recomputing yields the same answer, and
// there is no stored copy to go stale or to have to migrate.
func planPinnedPlacement(ctx *domainContext) map[uuid.UUID]cpuallocator.Result {
	if ctx.placer == nil {
		return nil
	}
	var requests []cpuallocator.Request
	for _, intent := range plannedIntents(ctx) {
		// The demand set carries the controller's intent only -- zedmanager
		// cannot see the operator's /persist override -- so whether a workload
		// is pinned, and how, is still resolved here.
		if !cpuIntentPinned(intent) {
			continue
		}
		placement, err := placementForIntent(intent)
		if err == nil {
			err = validateVCPUCount(placement, intent.vcpus)
		}
		if err != nil {
			// A workload whose intent cannot be satisfied is not part of the
			// plan, and its own activation is what reports that to the
			// controller. It is still logged here, because leaving it out also
			// changes where every other workload lands, and the plan file would
			// otherwise be unexplainable.
			log.Warnf("CPU planning: %s is left out of the plan: %v",
				intent.displayName, err)
			continue
		}
		// Thread-granular workloads are planned too (as ModeShared). Nothing
		// applies their planned assignment -- they are still allocated on
		// arrival -- but they do take CPUs exclusively, so the housekeeping set
		// derived from this plan has to account for them.
		requests = append(requests, cpuallocator.Request{
			UUID:     intent.id,
			NumVCPUs: intent.vcpus,
			Mode:     placement.Mode,
			NUMA:     placement.NUMA,
		})
	}
	if len(requests) == 0 {
		return nil
	}
	return ctx.placer.Plan(requests)
}

// claimPlannedPlacement returns the planned assignment for a workload if it can
// be taken as planned, i.e. every CPU the plan set aside for it is still free.
//
// A planned assignment is only usable while the plan and reality still agree.
// Workloads already running cannot be moved -- their vCPU threads are pinned and
// their guest was told a fixed topology at launch -- so if something else now
// holds a CPU this workload was planned onto, the plan cannot be applied as-is
// and the caller falls back to placing it among whatever is free. That fallback
// is the situation the optimality signal exists to report.
//
// vcpus is the count from the DomainConfig the workload is about to be created
// from. The plan is computed from zedmanager's demand set, which is a separate
// publication, so after a vCPU-count change the two can disagree for a moment.
// An assignment of the wrong size would be applied anyway and then contradict
// the -smp topology the guest is launched with, so QEMU would refuse to start
// and the retry would reuse the same stale assignment forever.
func claimPlannedPlacement(ctx *domainContext, id uuid.UUID, vcpus int,
	plan map[uuid.UUID]cpuallocator.Result) *cpuallocator.Assignment {
	result, planned := plan[id]
	if !planned || result.Status != cpuallocator.Success ||
		result.Assignment == nil {
		return nil
	}
	if len(result.Assignment.OrderedHostCPUs) != vcpus {
		log.Noticef("CPU planning: the plan for %s is for %d vCPUs but its config "+
			"asks for %d; placing it among free CPUs instead", id,
			len(result.Assignment.OrderedHostCPUs), vcpus)
		return nil
	}
	held := map[uint32]bool{}
	for _, cpu := range ctx.placer.DedicatedSet() {
		held[uint32(cpu)] = true
	}
	for _, cpu := range result.Assignment.OrderedHostCPUs {
		if held[uint32(cpu)] {
			return nil
		}
	}
	for _, cpu := range result.Assignment.ParkedCPUs {
		if held[uint32(cpu)] {
			return nil
		}
	}
	return result.Assignment
}

// plannedSlotBlockers names the workloads holding CPUs the plan set aside for
// another one, which is exactly the set that has to be restarted for a repack to
// free that slot.
//
// It is only for the report: "a repack would fix this" without naming who is in
// the way leaves the operator to work it out from the plan file, and nothing on
// the device restarts workloads by itself. Names are taken from the same set the
// plan was computed over, so a holder that has no DomainConfig here is still
// named; a holder that cannot be named at all is skipped rather than reported as
// a UUID nobody recognises.
func plannedSlotBlockers(ctx *domainContext, planned *cpuallocator.Assignment) []string {
	if ctx.placer == nil || planned == nil {
		return nil
	}
	names := map[uuid.UUID]string{}
	for _, intent := range plannedIntents(ctx) {
		names[intent.id] = intent.displayName
	}
	var blockers []string
	seen := map[uuid.UUID]bool{}
	for _, cpu := range assignmentCPUs(planned) {
		id, held := ctx.placer.HolderOf(cputopology.LCPU(cpu))
		if !held || seen[id] {
			continue
		}
		seen[id] = true
		if name := names[id]; name != "" {
			blockers = append(blockers, name)
		}
	}
	sort.Strings(blockers)
	return blockers
}

// emulatorHousekeepingCPUs is the CPU set a pinned VM's emulator/IO threads may
// be pinned to under io_placement=housekeeping.
//
// It deliberately is not "whatever is free right now". The set is chosen when
// the VM activates and is never revisited for a pinned VM -- only non-pinned VMs
// get their cpuset redistributed -- so a workload that starts later and takes
// CPUs of its own would find this VM's emulator threads already running on them,
// which is exactly the interference dedicated CPUs exist to prevent.
//
// The CPUs reserved for EVE's own services are therefore preferred: no workload
// can ever be given one, so a set drawn from them cannot be invalidated by a
// later deployment. Only when the node reserves none does this fall back to the
// CPUs no *currently configured* pinned workload was planned onto -- which is
// stable against start order but not against a workload deployed later, and is
// still better than leaving the emulator threads on the hot vCPU cores.
func emulatorHousekeepingCPUs(ctx *domainContext, plan map[uuid.UUID]cpuallocator.Result) []uint32 {
	if reserved := reservedForEVECPUs(ctx); len(reserved) > 0 {
		return reserved
	}
	planned := map[uint32]bool{}
	for _, result := range plan {
		if result.Status != cpuallocator.Success || result.Assignment == nil {
			continue
		}
		for _, cpu := range assignmentCPUs(result.Assignment) {
			planned[cpu] = true
		}
	}
	var out []uint32
	for _, cpu := range housekeepingCPUs(ctx) {
		if !planned[cpu] {
			out = append(out, cpu)
		}
	}
	return out
}

// reservedForEVECPUs is the low range of logical CPUs withheld from workloads,
// where EVE's own services run. The allocator applies the same lower bound, so
// these CPUs are the only ones guaranteed to stay free of every workload for as
// long as the node runs.
func reservedForEVECPUs(ctx *domainContext) []uint32 {
	var out []uint32
	for cpu := uint32(0); cpu < ctx.cpusReserved; cpu++ {
		out = append(out, cpu)
	}
	return out
}

// publishCPUPlan mirrors the plan to /run for inspection. Failures are not
// fatal: the plan is a diagnostic, and refusing to place a workload because its
// description could not be written would be worse than not writing it.
func publishCPUPlan(ctx *domainContext, plan map[uuid.UUID]cpuallocator.Result) {
	if plan == nil {
		_ = os.Remove(cpuPlanFile)
		return
	}
	// Described from the same set the plan was computed over, so a workload
	// that is planned but has no DomainConfig yet is still named here.
	names := map[uuid.UUID]string{}
	modes := map[uuid.UUID]string{}
	vcpus := map[uuid.UUID]int{}
	for _, intent := range plannedIntents(ctx) {
		names[intent.id] = intent.displayName
		vcpus[intent.id] = intent.vcpus
		if placement, err := placementForIntent(intent); err == nil {
			modes[intent.id] = placement.Mode.String()
		}
	}

	out := cpuPlan{
		Comment: "Derived CPU placement plan, recomputed from the app configs and " +
			"the CPU topology. Diagnostic only: nothing reads this file back.",
	}
	for id, result := range plan {
		entry := plannedPlacement{
			UUID:        id.String(),
			DisplayName: names[id],
			Mode:        modes[id],
			VCPUs:       vcpus[id],
			Status:      result.Status.String(),
			Message:     result.Message,
		}
		if result.Assignment != nil {
			for _, cpu := range result.Assignment.OrderedHostCPUs {
				entry.HostCPUs = append(entry.HostCPUs, uint32(cpu))
			}
			for _, cpu := range result.Assignment.ParkedCPUs {
				entry.ParkedCPUs = append(entry.ParkedCPUs, uint32(cpu))
			}
		}
		out.Workloads = append(out.Workloads, entry)
	}
	// Stable output so a diff between two boots is meaningful.
	sort.Slice(out.Workloads, func(i, j int) bool {
		return out.Workloads[i].UUID < out.Workloads[j].UUID
	})

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		log.Errorf("publishCPUPlan: marshal failed: %v", err)
		return
	}
	tmp := cpuPlanFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		log.Errorf("publishCPUPlan: write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, cpuPlanFile); err != nil {
		log.Errorf("publishCPUPlan: rename failed: %v", err)
	}
}

// assignmentCPUs is every CPU an assignment occupies: the ones backing vCPUs
// plus the siblings it parks. Parked siblings count as occupied -- that is the
// point of asking for whole cores -- so they must be reserved too, or another
// workload would be free to take them.
func assignmentCPUs(a *cpuallocator.Assignment) []uint32 {
	cpus := make([]uint32, 0, len(a.OrderedHostCPUs)+len(a.ParkedCPUs))
	for _, cpu := range a.OrderedHostCPUs {
		cpus = append(cpus, uint32(cpu))
	}
	for _, cpu := range a.ParkedCPUs {
		cpus = append(cpus, uint32(cpu))
	}
	return cpus
}
