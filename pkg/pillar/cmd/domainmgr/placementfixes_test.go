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
// isolation_tier or full_pcpus_only while leaving cpu_policy unset. Keying the
// resolution off cpu_policy alone dropped every other field without a word --
// including the two refusals that exist precisely so a workload never runs
// believing it got a guarantee it did not.
func TestPlacementFor_PolicyWithoutCPUPolicyIsNotIgnored(t *testing.T) {
	isolatePinningOverride(t)

	tests := []struct {
		name   string
		policy types.CPUPlacementPolicy
		code   string
	}{
		{
			name: "hard isolation tier",
			policy: types.CPUPlacementPolicy{
				IsolationTier: types.CPUIsolationTierHard,
			},
			code: types.ErrorCodeCPUIsolationTierUnavailable,
		},
		{
			name: "protect disruption policy",
			policy: types.CPUPlacementPolicy{
				DisruptionPolicy: types.CPUDisruptionPolicyProtect,
			},
			code: types.ErrorCodeCPUPolicyInvalid,
		},
		{
			name: "whole cores without a dedicated policy",
			policy: types.CPUPlacementPolicy{
				FullPCPUsOnly: true, ThreadsPerCore: 1,
			},
			code: types.ErrorCodeCPUPolicyInvalid,
		},
		{
			name: "single NUMA node without a dedicated policy",
			policy: types.CPUPlacementPolicy{
				NUMAPolicy: types.CPUNUMAPolicySingleNode,
			},
			code: types.ErrorCodeCPUPolicyInvalid,
		},
		{
			name: "threads per core out of range",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
				ThreadsPerCore: 4,
			},
			code: types.ErrorCodeCPUPolicyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := pinnedConfigForTest("policy-"+tt.name, tt.policy)
			_, err := placementFor(&config)
			var perr *placementError
			if !errors.As(err, &perr) {
				t.Fatalf("want a placement error, got %v", err)
			}
			if perr.Code != tt.code {
				t.Errorf("want code %q, got %q (%v)", tt.code, perr.Code, err)
			}
		})
	}
}

// A shared policy with no other field set is a complete, satisfiable intent: the
// workload runs unpinned. Rejecting it would refuse the one policy that asks for
// nothing.
func TestPlacementFor_SharedPolicyIsAccepted(t *testing.T) {
	isolatePinningOverride(t)
	config := pinnedConfigForTest("shared", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyShared,
	})
	placement, err := placementFor(&config)
	if err != nil {
		t.Fatalf("a shared policy must be accepted: %v", err)
	}
	if placement.TopologyAware {
		t.Error("a shared policy is not topology-aware")
	}
}

// The plan ranks thread-granular workloads last but does account for them.
// Allocating one on arrival instead of taking its planned CPUs hands it the
// lowest-numbered free threads -- exactly the cores the plan set aside whole for
// a whole-core workload -- so which of the two started first decided which one
// failed.
func TestAllocateCPUs_LegacyPinningTakesItsPlannedCPUs(t *testing.T) {
	isolatePinningOverride(t)
	ps := testPubSub(t)

	// Two vCPUs each: a whole-core workload needs one full core, the legacy one
	// takes two individual threads.
	wholeCore := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	legacy := pinnedConfigForTest("legacy", types.CPUPlacementPolicy{})

	ctx := &domainContext{
		placer:                      testPlacer(t),
		cpuTopologyPinningSupported: true,
		cpuPinningSupported:         true,
		pubDomainStatus:             testPublication(t, ps, types.DomainStatus{}),
		subDomainConfig:             testDomainConfigSub(t, ps, wholeCore, legacy),
	}

	// The legacy workload activates first, when nothing is running.
	var legacyStatus types.DomainStatus
	if err := assignCPUs(ctx, &legacy, &legacyStatus); err != nil {
		t.Fatalf("legacy placement failed: %v", err)
	}
	var wholeCoreStatus types.DomainStatus
	if err := assignCPUs(ctx, &wholeCore, &wholeCoreStatus); err != nil {
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

// A plan entry sized for a different vCPU count must not be applied: the guest
// is launched with an -smp topology derived from the assignment, so a mismatch
// makes QEMU refuse to start, and the retry would reuse the same stale
// assignment forever.
func TestClaimPlannedPlacement_RejectsAStaleVCPUCount(t *testing.T) {
	ctx := &domainContext{placer: testPlacer(t)}
	id := uuid.NewV5(uuid.NamespaceOID, "resized")
	plan := map[uuid.UUID]cpuallocator.Result{id: plannedOn(0, 4)}

	if got := claimPlannedPlacement(ctx, id, 2, plan); got == nil {
		t.Fatal("a plan for the configured vCPU count must be claimable")
	}
	if got := claimPlannedPlacement(ctx, id, 4, plan); got != nil {
		t.Errorf("a plan for 2 vCPUs must not be claimed for 4, got %v",
			got.OrderedHostCPUs)
	}
}

// A parked SMT sibling is consumed by the workload that parked it. A plan slot
// whose parked CPU is held by someone else therefore cannot be taken.
func TestClaimPlannedPlacement_ParkedCPUHeldBlocksTheClaim(t *testing.T) {
	placer := testPlacer(t)
	ctx := &domainContext{placer: placer}
	other := uuid.NewV5(uuid.NamespaceOID, "other")
	if err := placer.Reserve(other, []uint32{4}); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	id := uuid.NewV5(uuid.NamespaceOID, "onepercore")
	plan := map[uuid.UUID]cpuallocator.Result{id: {
		Status: cpuallocator.Success,
		Assignment: &cpuallocator.Assignment{
			OrderedHostCPUs: []cputopology.LCPU{0},
			ParkedCPUs:      []cputopology.LCPU{4},
		},
	}}
	if got := claimPlannedPlacement(ctx, id, 1, plan); got != nil {
		t.Errorf("the claim must fail while CPU 4 is held elsewhere, got %v",
			got.OrderedHostCPUs)
	}
}

// The housekeeping IO set is chosen when the workload activates and never
// revisited, so it has to be drawn from CPUs no workload can ever be given.
// Anything else is invalidated by the next deployment.
func TestEmulatorHousekeepingCPUs_PrefersTheCPUsReservedForEVE(t *testing.T) {
	ctx := &domainContext{placer: testPlacer(t), cpusReserved: 2}
	got := emulatorHousekeepingCPUs(ctx, nil)
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("want the reserved CPUs [0 1], got %v", got)
	}
}

// A synthesized topology cannot say which CPUs are SMT siblings, so a whole-core
// request placed against it would park nothing and share cores while reporting
// an optimal placement.
func TestAssignCPUs_WholeCoreRefusedOnDegradedTopology(t *testing.T) {
	isolatePinningOverride(t)
	ctx := &domainContext{
		placer:                      testPlacer(t),
		cpuTopologyPinningSupported: true,
		cpuTopologyDegraded:         true,
	}
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	var status types.DomainStatus

	err := assignCPUs(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUTopologyUnsupported {
		t.Fatalf("want %q, got %v", types.ErrorCodeCPUTopologyUnsupported, err)
	}
	if len(status.VmConfig.CPUs) != 0 {
		t.Errorf("a refused placement must reserve nothing, got %v",
			status.VmConfig.CPUs)
	}
}

// releaseCPUs is the single release path, so it must leave no pin state behind.
// A stale CPUsPinned with the housekeeping set in VmConfig.CPUs is read by the
// post-restart reseed as "these are exclusively mine", reserving most of the
// node to one workload.
func TestReleaseCPUs_ClearsThePinnedFlag(t *testing.T) {
	isolatePinningOverride(t)
	ps := testPubSub(t)
	ctx := &domainContext{
		placer:           testPlacer(t),
		pubCPUPoolStatus: testPublication(t, ps, types.CPUPoolStatus{}),
	}
	config := pinnedConfigForTest("released", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion
	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("placement failed: %v", err)
	}
	if !status.VmConfig.CPUsPinned {
		t.Fatal("precondition: the workload should be marked pinned")
	}

	releaseCPUs(ctx, &status)
	if status.VmConfig.CPUsPinned {
		t.Error("CPUsPinned must be cleared with the rest of the pin state")
	}
}

func claimedPlan(ctx *domainContext) map[uuid.UUID]*cpuallocator.Assignment {
	out := map[uuid.UUID]*cpuallocator.Assignment{}
	for id, result := range planPinnedPlacement(ctx) {
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
