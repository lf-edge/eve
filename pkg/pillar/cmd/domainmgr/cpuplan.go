// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

// cpuPlanFile is where the current placement plan is mirrored, for an operator
// to see what the device decided and why a workload is where it is. Nothing
// reads it back.
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
// the controller intends to run on this node, keyed by UUID.
//
// zedmanager's demand set names the apps intended to run from the moment their
// config arrives; a DomainConfig is published only once an app's volumes and
// network are ready, so planning over the DomainConfigs alone would make the
// layout depend on download order. Each source covers what the other may not
// have yet: an app is planned if the demand set names it or its DomainConfig
// asks for activation, and the DomainConfig's intent wins, being the one the
// workload is created from.
func plannedIntents(ctx *domainContext) map[uuid.UUID]cpuIntent {
	intents := map[uuid.UUID]cpuIntent{}
	if item, err := ctx.subCPUDemandSet.Get("global"); err == nil {
		for _, app := range item.(types.CPUDemandSet).Apps {
			intents[app.UUID] = intentOfDemand(app)
		}
	}
	ctx.subDomainConfig.Iterate(func(_ string, item interface{}) bool {
		config := item.(types.DomainConfig)
		id := config.UUIDandVersion.UUID
		if _, demanded := intents[id]; demanded || config.Activate {
			intents[id] = intentOfConfig(&config)
		}
		return true
	})
	return intents
}

// planFor computes the placement plan for every planned workload that gets
// CPUs of its own, whether or not it is running yet. The plan is a function of
// the planned set and the topology alone, so the same configuration lays out
// the same way whatever order its workloads start in.
func planFor(placer *cpuallocator.Placer, intents map[uuid.UUID]cpuIntent) map[uuid.UUID]cpuallocator.Result {
	var requests []cpuallocator.Request
	for _, intent := range intents {
		if !intent.ownsCPUs() {
			continue
		}
		placement, err := intent.placement()
		if err == nil {
			err = validateVCPUCount(placement, intent.vcpus)
		}
		if err != nil {
			// Its own activation reports the refusal; this explains the plan
			// file, where leaving it out moves every other workload.
			log.Warnf("CPU planning: %s is left out of the plan: %v",
				intent.displayName, err)
			continue
		}
		requests = append(requests, placement.request(intent, nil))
	}
	if len(requests) == 0 {
		return nil
	}
	return placer.Plan(requests)
}

// plannedOK reports whether the plan found a placement for a workload.
func plannedOK(plan map[uuid.UUID]cpuallocator.Result, id uuid.UUID) bool {
	r, ok := plan[id]
	return ok && r.Status == cpuallocator.Success && r.Assignment != nil
}

// plannedCPUs is every CPU the plan gives to a workload include accepts, or to
// any workload when include is nil.
func plannedCPUs(plan map[uuid.UUID]cpuallocator.Result,
	include func(uuid.UUID) bool) []cputopology.LCPU {
	var out []cputopology.LCPU
	for id := range plan {
		if plannedOK(plan, id) && (include == nil || include(id)) {
			out = append(out, plan[id].Assignment.CPUs()...)
		}
	}
	return out
}

// emulatorCPUs is where a VM's emulator and IO threads run under
// io_placement=housekeeping. They are pinned once, at start, so the set must
// stay free of every workload for as long as the VM runs: the CPUs reserved for
// EVE when the node has any, which no workload is ever given, else the
// housekeeping CPUs no configured workload is planned onto.
func emulatorCPUs(placer *cpuallocator.Placer, plan map[uuid.UUID]cpuallocator.Result) []uint32 {
	if reserved := placer.ReservedCPUs(); len(reserved) > 0 {
		return lcpusToUint32(reserved)
	}
	planned := plannedCPUs(plan, nil)
	hk, _ := placer.HousekeepingCPUs()
	var out []uint32
	for _, cpu := range hk {
		if !slices.Contains(planned, cpu) {
			out = append(out, uint32(cpu))
		}
	}
	return out
}

// publishCPUPlan mirrors the plan to /run. A failure is only logged: the file
// is a diagnostic.
func publishCPUPlan(view *placementView) {
	if len(view.plan) == 0 {
		_ = os.Remove(cpuPlanFile)
		return
	}
	out := cpuPlan{
		Comment: "Derived CPU placement plan, recomputed from the app configs and " +
			"the CPU topology. Diagnostic only: nothing reads this file back.",
	}
	for id, result := range view.plan {
		intent := view.intents[id]
		entry := plannedPlacement{
			UUID:        id.String(),
			DisplayName: intent.displayName,
			VCPUs:       intent.vcpus,
			Status:      result.Status.String(),
			Message:     result.Message,
		}
		if placement, err := intent.placement(); err == nil {
			entry.Mode = placement.Mode.String()
		}
		if result.Assignment != nil {
			entry.HostCPUs = lcpusToUint32(result.Assignment.OrderedHostCPUs)
			entry.ParkedCPUs = lcpusToUint32(result.Assignment.ParkedCPUs)
		}
		out.Workloads = append(out.Workloads, entry)
	}
	sort.Slice(out.Workloads, func(i, j int) bool {
		return out.Workloads[i].UUID < out.Workloads[j].UUID
	})
	data, err := json.MarshalIndent(out, "", "  ")
	if err == nil {
		err = fileutils.WriteRename(cpuPlanFile, data)
	}
	if err != nil {
		log.Errorf("publishCPUPlan: %v", err)
	}
}
