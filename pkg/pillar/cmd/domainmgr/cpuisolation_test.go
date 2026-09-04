// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// isolatedCPUsForTest is the isolated set as domainmgr holds it, for a context
// built alongside testPlacerIsolating.
func isolatedCPUsForTest(cpus ...uint32) []cputopology.LCPU {
	out := make([]cputopology.LCPU, 0, len(cpus))
	for _, c := range cpus {
		out = append(out, cputopology.LCPU(c))
	}
	return out
}

// hardIsolationConfig is a whole-core workload asking for the hard tier.
func hardIsolationConfig(name string) types.DomainConfig {
	return pinnedConfigForTest(name, types.CPUPlacementPolicy{
		Policy:        types.CPUPolicyDedicated,
		FullPCPUsOnly: true,
		IsolationTier: types.CPUIsolationTierHard,
	})
}

// The kernel-isolated cores are the whole point of the hard tier, so a workload
// that asks for it lands on them -- not merely on some whole core.
//
// testPlacer numbers thread 0 of core N as N and thread 1 as N+4, so core 3 is
// {3, 7}: the highest core, which an unconstrained placement would never reach
// first. That is what makes this test able to tell "placed on isolated cores"
// apart from "placed, and the isolated cores happened to be next in line".
func TestAssignCPUs_HardIsolationTakesTheIsolatedCores(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	config := hardIsolationConfig("isolated-app")
	ctx := &domainContext{
		placer:                      testPlacerIsolating(t, 3, 7),
		isolatedCPUs:                isolatedCPUsForTest(3, 7),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := assignCPUs(ctx, &config, &status); err != nil {
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
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	// Cores 1, 2 and 3 isolated ({1,5}, {2,6}, {3,7}), leaving core 0 as the
	// only core an ordinary workload may have.
	config := pinnedConfigForTest("ordinary", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	isolated := []uint32{1, 2, 3, 5, 6, 7}
	ctx := &domainContext{
		placer:                      testPlacerIsolating(t, isolated...),
		isolatedCPUs:                isolatedCPUsForTest(isolated...),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := assignCPUs(ctx, &config, &status); err != nil {
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
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	first := pinnedConfigForTest("first", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	second := pinnedConfigForTest("second", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	isolated := []uint32{1, 2, 3, 5, 6, 7}
	ctx := &domainContext{
		placer:                      testPlacerIsolating(t, isolated...),
		isolatedCPUs:                isolatedCPUsForTest(isolated...),
		subDomainConfig:             testDomainConfigSub(t, ps, first, second),
		cpuTopologyPinningSupported: true,
	}
	var firstStatus, secondStatus types.DomainStatus
	firstStatus.UUIDandVersion = first.UUIDandVersion
	secondStatus.UUIDandVersion = second.UUIDandVersion

	if err := assignCPUs(ctx, &first, &firstStatus); err != nil {
		t.Fatalf("the first workload must be placeable: %v", err)
	}
	err := assignCPUs(ctx, &second, &secondStatus)
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

// A node with no kernel isolation cannot serve the hard tier and cannot acquire
// one while running, so the refusal has to name the kernel command line rather
// than suggest freeing CPUs.
func TestAssignCPUs_HardIsolationRefusedWithoutIsolatedCPUs(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	config := hardIsolationConfig("wants-isolation")
	ctx := &domainContext{
		placer:                      testPlacer(t),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := assignCPUs(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) ||
		perr.Code != types.ErrorCodeCPUIsolationTierUnavailable {
		t.Fatalf("want %q, got %v", types.ErrorCodeCPUIsolationTierUnavailable, err)
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
	ctx := &domainContext{
		placer:       testPlacerIsolating(t, 3, 7),
		isolatedCPUs: isolatedCPUsForTest(3, 7),
	}
	got := housekeepingCPUs(ctx)
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
	ctx := &domainContext{
		placer:       testPlacerIsolating(t, all...),
		isolatedCPUs: isolatedCPUsForTest(all...),
	}
	if got := housekeepingCPUs(ctx); len(got) != len(all) {
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

// The operator flip: on a node booted with isolcpus, cpu.pinning.use.isolated
// puts pinned workloads on the isolated cores without the controller having to
// send isolation_tier -- which is the whole point, since a pin_cpu-only
// controller cannot express it.
func TestApplyIsolatedPoolFlip_PutsWholeCoreWorkloadsOnIsolatedCores(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	// pin_cpu only, no policy: the temporary default resolves it to whole-core.
	config := pinnedConfigForTest("flipped", types.CPUPlacementPolicy{})
	ctx := &domainContext{
		placer:                      testPlacerIsolating(t, 3, 7),
		isolatedCPUs:                isolatedCPUsForTest(3, 7),
		useIsolatedCPUs:             true,
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("the flip must place the workload on the isolated core: %v", err)
	}
	if !equalCPUSets(status.OrderedCPUs, []uint32{3, 7}) {
		t.Errorf("want the isolated core [3 7], got %v", status.OrderedCPUs)
	}
}

// With the flip off -- the default -- nothing changes: the isolated cores stay
// reserved and the workload takes an ordinary one.
func TestApplyIsolatedPoolFlip_OffLeavesIsolatedCoresAlone(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	config := pinnedConfigForTest("not-flipped", types.CPUPlacementPolicy{})
	ctx := &domainContext{
		placer:                      testPlacerIsolating(t, 3, 7),
		isolatedCPUs:                isolatedCPUsForTest(3, 7),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("placement must still succeed: %v", err)
	}
	if len(intersectIsolated(status.OrderedCPUs, []uint32{3, 7})) != 0 {
		t.Errorf("the flip is off, so %v must not include an isolated CPU",
			status.OrderedCPUs)
	}
}

// The flip set on a node whose kernel isolates nothing must not fail the
// workload: it is an operator preference for the node, most likely set before
// the reboot that adds isolcpus, not a per-workload guarantee.
func TestApplyIsolatedPoolFlip_NoIsolatedCPUsIsNotFatal(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	config := pinnedConfigForTest("no-isolation", types.CPUPlacementPolicy{})
	ctx := &domainContext{
		placer:                      testPlacer(t),
		useIsolatedCPUs:             true,
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("the flip must not fail a workload on a node without isolcpus: %v",
			err)
	}
	if len(status.OrderedCPUs) == 0 {
		t.Error("the workload must still be placed")
	}
}

// A thread-granular workload is never promoted: kernel isolation means nothing
// on a core whose sibling the kernel still schedules.
func TestApplyIsolatedPoolFlip_SkipsThreadGranular(t *testing.T) {
	ctx := &domainContext{
		placer:          testPlacerIsolating(t, 3, 7),
		isolatedCPUs:    isolatedCPUsForTest(3, 7),
		useIsolatedCPUs: true,
	}
	shared := resolvedPlacement{TopologyAware: false}
	if got := applyIsolatedPoolFlip(ctx, shared, "thread-granular"); got.RequireIsolated {
		t.Error("a thread-granular placement must not be promoted to isolated cores")
	}
}

func intersectIsolated(got []uint32, isolated []uint32) []uint32 {
	var out []uint32
	for _, c := range got {
		if containsUint32(isolated, c) {
			out = append(out, c)
		}
	}
	return out
}
