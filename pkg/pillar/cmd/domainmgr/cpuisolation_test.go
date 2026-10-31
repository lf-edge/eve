// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// hardIsolationConfig is a pinned whole-core workload asking for the isolated
// pool.
func hardIsolationConfig(name string) types.DomainConfig {
	return pinnedConfigForTest(name, types.CPUPlacementPolicy{
		Policy: types.CPUPolicyIsolated, Pinned: true,
		FullPCPUsOnly: true,
	})
}

// The kernel-isolated cores are the whole point of the isolated pool, so a
// workload that asks for it lands on them -- not merely on some whole core.
//
// testPlacer numbers thread 0 of core N as N and thread 1 as N+4, so core 3 is
// {3, 7}: the highest core, which an unconstrained placement would never reach
// first. That is what makes this test able to tell "placed on isolated cores"
// apart from "placed, and the isolated cores happened to be next in line".
func TestAssignCPUs_HardIsolationTakesTheIsolatedCores(t *testing.T) {

	ps := testPubSub(t)
	config := hardIsolationConfig("isolated-app")
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacerIsolating(t, 3, 7)),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("a hard-isolation request must be placeable on an isolcpus node: %v", err)
	}
	want := []uint32{3, 7}
	if !equalCPUSets(status.OrderedCPUs, want) {
		t.Errorf("want the isolated core %v, got %v", want, status.OrderedCPUs)
	}
}

// The mirror image: a workload that did not ask for isolation must not be given
// isolated cores, even when they are the only whole cores left. Spending the
// operator's isolation on a workload that never wanted it leaves the workload
// that does unplaceable, which is the reason isolcpus was set at all.
func TestAssignCPUs_OrdinaryWorkloadDoesNotTakeIsolatedCores(t *testing.T) {

	ps := testPubSub(t)
	// Cores 1, 2 and 3 isolated ({1,5}, {2,6}, {3,7}), leaving core 0 as the
	// only core an ordinary workload may have.
	config := pinnedConfigForTest("ordinary", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	isolated := []uint32{1, 2, 3, 5, 6, 7}
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacerIsolating(t, isolated...)),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("the one unisolated core must still be placeable: %v", err)
	}
	if !equalCPUSets(status.OrderedCPUs, []uint32{0, 4}) {
		t.Errorf("want the unisolated core [0 4], got %v", status.OrderedCPUs)
	}
}

// A second ordinary whole-core workload has nowhere to go once core 0 is taken,
// and the shortage has to say why: the operator otherwise sees six idle CPUs and
// an "insufficient" with nothing connecting the two.
func TestAssignCPUs_IsolatedCoresExplainAnOrdinaryShortage(t *testing.T) {

	ps := testPubSub(t)
	first := pinnedConfigForTest("first", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	second := pinnedConfigForTest("second", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	isolated := []uint32{1, 2, 3, 5, 6, 7}
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacerIsolating(t, isolated...)),
		subDomainConfig:             testDomainConfigSub(t, ps, first, second),
		cpuTopologyPinningSupported: true,
	})
	var firstStatus, secondStatus types.DomainStatus
	firstStatus.UUIDandVersion = first.UUIDandVersion
	secondStatus.UUIDandVersion = second.UUIDandVersion

	if err := ctx.cpuPlacement.assign(ctx, &first, &firstStatus); err != nil {
		t.Fatalf("the first workload must be placeable: %v", err)
	}
	err := ctx.cpuPlacement.assign(ctx, &second, &secondStatus)
	var perr *placementError
	if !errors.As(err, &perr) {
		t.Fatalf("the second workload has no unisolated core left, want a "+
			"placement error, got %v", err)
	}
	if !strings.Contains(perr.Msg, "kernel-isolated") {
		t.Errorf("the shortage must name the withheld isolated cores, got %q",
			perr.Msg)
	}
}

// A node with no kernel isolation cannot serve the isolated pool and cannot
// acquire one while running, so the refusal has to name the kernel command line rather
// than suggest freeing CPUs.
func TestAssignCPUs_HardIsolationRefusedWithoutIsolatedCPUs(t *testing.T) {

	ps := testPubSub(t)
	config := hardIsolationConfig("wants-isolation")
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) ||
		perr.Status != types.CPUPlacementStatusIsolationUnavailable {
		t.Fatalf("want %q, got %v", types.CPUPlacementStatusIsolationUnavailable, err)
	}
	if !strings.Contains(perr.Msg, "isolcpus") {
		t.Errorf("the refusal must name the boot parameter that would fix it, "+
			"got %q", perr.Msg)
	}
	if len(status.VmConfig.CPUs) != 0 || len(status.OrderedCPUs) != 0 {
		t.Errorf("a refused placement must not reserve CPUs, got %v/%v",
			status.VmConfig.CPUs, status.OrderedCPUs)
	}
}

// The non-pinned workloads and the emulator threads run on the housekeeping set,
// and the kernel honours an explicit affinity onto an isolated CPU -- isolcpus
// only keeps the load balancer away. So the set has to exclude them, or every
// unpinned workload on the node lands on the cores the operator carved out.
func TestHousekeepingCPUs_ExcludesTheIsolatedSet(t *testing.T) {
	ctx := placementContext(t, &domainContext{
		cpuPlacement: newCPUPlacement(testPlacerIsolating(t, 3, 7)),
	})
	got := ctx.cpuPlacement.housekeeping()
	for _, cpu := range []uint32{3, 7} {
		if containsUint32(got, cpu) {
			t.Errorf("CPU %d is kernel-isolated and must not be in the "+
				"housekeeping set %v", cpu, got)
		}
	}
	if len(got) != 6 {
		t.Errorf("want the other six CPUs, got %v", got)
	}
}

// An isolcpus covering every CPU is a misconfiguration, not a runtime state. An
// empty housekeeping set would give every non-pinned workload an empty cpuset,
// so the set falls back to the isolated CPUs rather than to nothing.
func TestHousekeepingCPUs_FallsBackWhenEverythingIsIsolated(t *testing.T) {
	all := []uint32{0, 1, 2, 3, 4, 5, 6, 7}
	ctx := placementContext(t, &domainContext{
		cpuPlacement: newCPUPlacement(testPlacerIsolating(t, all...)),
	})
	if got := ctx.cpuPlacement.housekeeping(); len(got) != len(all) {
		t.Errorf("want every CPU back rather than an empty cpuset, got %v", got)
	}
}

func equalCPUSets(got []uint32, want []uint32) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !containsUint32(got, w) {
			return false
		}
	}
	return true
}
