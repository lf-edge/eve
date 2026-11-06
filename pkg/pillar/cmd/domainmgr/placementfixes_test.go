// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// The placement fields are independent on the wire, so a controller can set
// full_pcpus_only or numa_policy while leaving cpu_policy unset. That is not a
// legacy request, which sends only pin_cpu: the fields must be refused, not
// dropped and not turned into a dedicated request they were never sent with.
func TestPlacementFor_PolicyWithoutCPUPolicyIsNotIgnored(t *testing.T) {

	tests := []struct {
		name   string
		policy types.CPUPlacementPolicy
		status types.CPUPlacementStatus
	}{
		{
			name: "whole cores without a dedicated policy",
			policy: types.CPUPlacementPolicy{
				FullPCPUsOnly: true, ThreadsPerCore: 1,
			},
			status: types.CPUPlacementStatusPolicyInvalid,
		},
		{
			name: "single NUMA node without a dedicated policy",
			policy: types.CPUPlacementPolicy{
				NUMAPolicy: types.CPUNUMAPolicySingleNode,
			},
			status: types.CPUPlacementStatusPolicyInvalid,
		},
		{
			name: "threads per core out of range",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
				ThreadsPerCore: 4,
			},
			status: types.CPUPlacementStatusPolicyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := pinnedConfigForTest("policy-"+tt.name, tt.policy)
			_, err := intentOfConfig(&config).placement()
			var perr *placementError
			if !errors.As(err, &perr) {
				t.Fatalf("want a placement error, got %v", err)
			}
			if perr.Status != tt.status {
				t.Errorf("want %q, got %q (%v)", tt.status, perr.Status, err)
			}
		})
	}
}

// A shared policy with no other field set is a complete, satisfiable intent: the
// workload runs unpinned. Rejecting it would refuse the one policy that asks for
// nothing.
func TestPlacementFor_SharedPolicyIsAccepted(t *testing.T) {
	config := pinnedConfigForTest("shared", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyHousekeeping,
	})
	placement, err := intentOfConfig(&config).placement()
	if err != nil {
		t.Fatalf("a shared policy must be accepted: %v", err)
	}
	if placement.Mode != cpuallocator.ModeShared {
		t.Error("a shared policy takes no whole cores")
	}
}

// The plan ranks thread-granular workloads last but does account for them.
// Allocating one on arrival instead of taking its planned CPUs hands it the
// lowest-numbered free threads -- exactly the cores the plan set aside whole for
// a whole-core workload -- so which of the two started first decided which one
// failed.
func TestAllocateCPUs_LegacyPinningTakesItsPlannedCPUs(t *testing.T) {
	ps := testPubSub(t)

	// Two vCPUs each: a whole-core workload needs one full core, the legacy one
	// takes two individual threads.
	wholeCore := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	legacy := pinnedConfigForTest("legacy", legacyPinCPU)
	wholeCore.Activate = true
	legacy.Activate = true

	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		cpuTopologyPinningSupported: true,
		cpuPinningSupported:         true,
		pubDomainStatus:             testPublication(t, ps, types.DomainStatus{}),
		subDomainConfig:             testDomainConfigSub(t, ps, wholeCore, legacy),
	})

	// The legacy workload activates first, when nothing is running.
	var legacyStatus types.DomainStatus
	if err := ctx.cpuPlacement.assign(ctx, &legacy, &legacyStatus); err != nil {
		t.Fatalf("legacy placement failed: %v", err)
	}
	var wholeCoreStatus types.DomainStatus
	if err := ctx.cpuPlacement.assign(ctx, &wholeCore, &wholeCoreStatus); err != nil {
		t.Fatalf("whole-core placement failed after the legacy one: %v", err)
	}

	planned := claimedPlan(ctx)
	want := planned[legacy.UUIDandVersion.UUID]
	if want == nil {
		t.Fatal("the plan says nothing about the legacy workload")
	}
	for _, cpu := range legacyStatus.VmConfig.CPUs {
		if !containsLCPU(want.OrderedHostCPUs, cpu) {
			t.Errorf("legacy workload got CPU %d, which the plan gave to someone "+
				"else (planned %v, whole-core got %v)", cpu, want.OrderedHostCPUs,
				wholeCoreStatus.VmConfig.CPUs)
		}
	}
	for _, cpu := range wholeCoreStatus.OrderedCPUs {
		if containsUint32(legacyStatus.VmConfig.CPUs, cpu) {
			t.Errorf("whole-core workload and legacy workload share CPU %d", cpu)
		}
	}
}

// The plan is computed from the DomainConfig the workload is created from, so a
// demand set that has not caught up with a vCPU change cannot hand it an
// assignment of the wrong size, which would contradict the -smp topology the
// guest is launched with.
func TestAssign_PlansFromTheConfigItIsCreatedFrom(t *testing.T) {
	demand := wholeCoreDemand("resized", 2)
	config := pinnedConfigForTest("resized", demand.CPUPlacement)
	config.VmConfig.VCpus = 4
	ps := testPubSub(t)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subCPUDemandSet:             testCPUDemandSub(t, ps, demand),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion
	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("placement failed: %v", err)
	}
	if len(status.OrderedCPUs) != 4 || status.VMTopology.Cores*status.VMTopology.Threads != 4 {
		t.Errorf("want 4 vCPUs placed, got %v with topology %+v",
			status.OrderedCPUs, status.VMTopology)
	}
}

// The housekeeping IO set is chosen when the workload activates and never
// revisited, so it has to be drawn from CPUs no workload can ever be given.
// Anything else is invalidated by the next deployment.
func TestEmulatorCPUs_PrefersTheCPUsReservedForEVE(t *testing.T) {
	placer, err := cpuallocator.NewPlacer(testTopology(), 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := emulatorCPUs(placer, nil)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("want the reserved CPUs [0 1], got %v", got)
	}
}

// A node whose CPU topology could not be read reports it as unknown, and gives
// no workload CPUs of its own: not whole cores, which a synthesized topology
// could not tell apart, and not single CPUs or legacy pin_cpu either, since a
// controller must not have sent any of them. Its capabilities say it cannot
// place whole cores.
func TestAssignCPUs_PinningRefusedOnDegradedTopology(t *testing.T) {
	topo := testTopology()
	topo.Degraded = true
	for name, policy := range map[string]types.CPUPlacementPolicy{
		"whole cores":                       {Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true},
		"one CPU at a time, legacy pin_cpu": legacyPinCPU,
	} {
		t.Run(name, func(t *testing.T) {
			placer, err := cpuallocator.NewPlacer(topo, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(placer)})
			config := pinnedConfigForTest("degraded-"+name, policy)
			var status types.DomainStatus

			err = ctx.cpuPlacement.assign(ctx, &config, &status)
			var perr *placementError
			if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusTopologyUnsupported {
				t.Fatalf("want %q, got %v", types.CPUPlacementStatusTopologyUnsupported, err)
			}
			if len(status.VmConfig.CPUs) != 0 {
				t.Errorf("a refused placement must reserve nothing, got %v",
					status.VmConfig.CPUs)
			}
		})
	}
}

// A shared workload never takes the pinned path, so its policy is checked before
// it is handed the housekeeping CPUs: pin_cpu=true on the shared pool is not
// implemented, and running it unpinned would drop the field silently.
func TestAssignCPUs_SharedPinnedRefused(t *testing.T) {
	ctx := placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(testPlacer(t)), cpuTopologyPinningSupported: true})
	config := pinnedConfigForTest("shared-pinned", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyHousekeeping, Pinned: true,
	})
	var status types.DomainStatus

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusPolicyInvalid {
		t.Fatalf("want %q, got %v", types.CPUPlacementStatusPolicyInvalid, err)
	}
	if len(status.VmConfig.CPUs) != 0 {
		t.Errorf("a refused workload must get no CPUs, got %v", status.VmConfig.CPUs)
	}
}

// A workload taking CPUs one at a time that does not fit is refused with a
// structured code and a retry condition, like a whole-core one: the controller
// must not have to parse prose to learn the node is short.
func TestAssignCPUs_ThreadGranularShortageHasACode(t *testing.T) {
	ps := testPubSub(t)
	config := pinnedConfigForTest("too-big", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true,
	})
	config.VCpus = 9 // testPlacer has 8 logical CPUs
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusInsufficient {
		t.Fatalf("want %q, got %v", types.CPUPlacementStatusInsufficient, err)
	}
	if retryConditionOf(t, err) == "" {
		t.Error("the shortage must carry a retry condition")
	}
}

// release is the single release path, so it must leave no CPU state behind: a
// stale field would have the post-restart reseed, or the app's info, read CPUs
// the workload no longer holds.
func TestRelease_LeavesNoCPUState(t *testing.T) {
	ps := testPubSub(t)
	config := pinnedConfigForTest("released", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true, ThreadsPerCore: 1,
	})
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		pubCPUPoolStatus:            testPublication(t, ps, types.CPUPoolStatus{}),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion
	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("placement failed: %v", err)
	}
	if status.CPUAssignment().Equal(types.CPUAssignment{}) {
		t.Fatal("precondition: the workload should hold CPUs")
	}

	ctx.cpuPlacement.release(ctx, &status)
	if !status.CPUAssignment().Equal(types.CPUAssignment{}) || len(status.VmConfig.CPUs) != 0 ||
		status.VMTopology.IsSet() || status.CPUPlacementStatus != types.CPUPlacementStatusUnspecified {
		t.Errorf("release left CPU state behind: %+v", status)
	}
	if ctx.cpuPlacement.placer.Holds(config.UUIDandVersion.UUID) {
		t.Error("release must give the CPUs back to the placer")
	}
}

func claimedPlan(ctx *domainContext) map[uuid.UUID]*cpuallocator.Assignment {
	out := map[uuid.UUID]*cpuallocator.Assignment{}
	for id, result := range planFor(ctx.cpuPlacement.placer, plannedIntents(ctx)) {
		if result.Status == cpuallocator.Success {
			out[id] = result.Assignment
		}
	}
	return out
}

func containsLCPU(cpus []cputopology.LCPU, want uint32) bool {
	for _, cpu := range cpus {
		if uint32(cpu) == want {
			return true
		}
	}
	return false
}

func containsUint32(cpus []uint32, want uint32) bool {
	for _, cpu := range cpus {
		if cpu == want {
			return true
		}
	}
	return false
}

// A one-thread-per-core workload holds the other thread of each of its cores so
// that nothing shares them, its own emulator and IO threads included: the parked
// siblings are held in the placer, recorded apart, and kept out of the cpuset.
// A domainmgr restart has to reseed them with the rest, or another workload
// could be given a thread on those cores.
func TestAssignCPUs_ParkedSiblingsAreHeldButNotInTheCpuset(t *testing.T) {
	ps := testPubSub(t)
	config := pinnedConfigForTest("one-per-core", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true, ThreadsPerCore: 1,
	})
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion
	status.DisplayName = config.DisplayName
	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("placement failed: %v", err)
	}
	if !equalCPUSets(status.VmConfig.CPUs, status.OrderedCPUs) {
		t.Errorf("the cpuset must be the vCPU CPUs %v only, got %v",
			status.OrderedCPUs, status.VmConfig.CPUs)
	}
	// testPlacer's core c is CPUs c and c+4.
	if len(status.ParkedCPUs) != config.VCpus {
		t.Fatalf("want one parked sibling per vCPU, got %v", status.ParkedCPUs)
	}
	for i, parked := range status.ParkedCPUs {
		if vcpu := status.OrderedCPUs[i]; parked%4 != vcpu%4 || parked == vcpu {
			t.Errorf("parked CPU %d is not the sibling of vCPU CPU %d", parked, vcpu)
		}
	}
	holders := ctx.cpuPlacement.placer.Holders()
	for _, c := range status.ParkedCPUs {
		if holders[cputopology.LCPU(c)] != config.UUIDandVersion.UUID {
			t.Errorf("parked CPU %d must stay held, got holders %v", c, holders)
		}
	}

	restarted := placementContext(t, &domainContext{
		cpuPlacement:    newCPUPlacement(testPlacer(t)),
		pubDomainStatus: testPublication(t, ps, types.DomainStatus{}),
	})
	if err := restarted.pubDomainStatus.Publish(status.Key(), status); err != nil {
		t.Fatal(err)
	}
	restarted.cpuPlacement.reseed(restarted)
	if got := restarted.cpuPlacement.placer.Holders(); len(got) != 2*config.VCpus {
		t.Errorf("a restart must reseed the vCPU CPUs and the parked siblings, got %v", got)
	}
}
