// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	uuid "github.com/satori/go.uuid"
)

func plannedOn(cpus ...cputopology.LCPU) cpuallocator.Result {
	return cpuallocator.Result{
		Status:     cpuallocator.Success,
		Assignment: &cpuallocator.Assignment{OrderedHostCPUs: cpus},
	}
}

// Regression: the emulator housekeeping set is computed once, when the VM
// activates, and is never recomputed for a pinned VM. Deriving it from what
// happens to be free at that moment therefore hands VM1's emulator/IO threads
// the very CPUs VM2 later takes as its dedicated cores.
func TestEmulatorHousekeepingCPUs_ExcludesPlannedPinnedCPUs(t *testing.T) {
	placer := testPlacer(t) // 4 SMT2 cores: {0,4} {1,5} {2,6} {3,7}
	ctx := &domainContext{placer: placer}

	running := uuid.NewV5(uuid.NamespaceOID, "running")
	notStartedYet := uuid.NewV5(uuid.NamespaceOID, "later")
	placer.Reserve(running, []uint32{0, 4})

	plan := map[uuid.UUID]cpuallocator.Result{
		running:       plannedOn(0, 4),
		notStartedYet: plannedOn(1, 5),
	}

	// The free set alone still offers the CPUs the second workload is planned
	// onto -- that is the leak.
	if free := housekeepingCPUs(ctx); !contains(free, 1) || !contains(free, 5) {
		t.Fatalf("precondition: the free set should still contain 1 and 5, got %v", free)
	}

	got := emulatorHousekeepingCPUs(ctx, plan)
	for _, cpu := range []uint32{0, 1, 4, 5} {
		if contains(got, cpu) {
			t.Errorf("housekeeping set %v must not contain pinned CPU %d", got, cpu)
		}
	}
	for _, cpu := range []uint32{2, 3, 6, 7} {
		if !contains(got, cpu) {
			t.Errorf("housekeeping set %v should still offer unclaimed CPU %d", got, cpu)
		}
	}
}

// A workload the plan could not place holds nothing, so it must not shrink the
// housekeeping set.
func TestEmulatorHousekeepingCPUs_IgnoresUnplaceableWorkloads(t *testing.T) {
	ctx := &domainContext{placer: testPlacer(t)}
	plan := map[uuid.UUID]cpuallocator.Result{
		uuid.NewV5(uuid.NamespaceOID, "toobig"): {
			Status: cpuallocator.Insufficient, Message: "need 8 free cores, have 4",
		},
	}
	if got := emulatorHousekeepingCPUs(ctx, plan); len(got) != 8 {
		t.Errorf("want all 8 CPUs available for housekeeping, got %v", got)
	}
}

func contains(cpus []uint32, want uint32) bool {
	for _, cpu := range cpus {
		if cpu == want {
			return true
		}
	}
	return false
}
