// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func poolOfKind(t *testing.T, status types.CPUPoolStatus,
	kind types.CPUPoolKind) types.CPUPoolUtilization {
	t.Helper()
	for _, pool := range status.Pools {
		if pool.Kind == kind {
			return pool
		}
	}
	t.Fatalf("no %s pool in %+v", kind, status.Pools)
	return types.CPUPoolUtilization{}
}

func publishedPools(t *testing.T, pub pubsub.Publication) types.CPUPoolStatus {
	t.Helper()
	item, err := pub.Get("global")
	if err != nil {
		t.Fatalf("the pool report was not published: %v", err)
	}
	status, ok := item.(types.CPUPoolStatus)
	if !ok {
		t.Fatalf("unexpected published type %T", item)
	}
	return status
}

// The pool report is what a controller uses to answer "will this workload fit?",
// so it has to be published, cover every pool, and say how many whole cores are
// left -- not just how many threads.
func TestPublishCPUPoolStatus(t *testing.T) {
	ps := testPubSub(t)
	pub := testPublication(t, ps, types.CPUPoolStatus{})
	ctx := placementContext(t, &domainContext{
		cpuPlacement:     newCPUPlacement(testPlacerIsolating(t, 2, 6)),
		pubCPUPoolStatus: pub,
	})
	// testPlacer numbers the siblings of core c as CPU c and CPU c+4.
	ctx.cpuPlacement.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "pinned"), []uint32{0, 4})

	ctx.cpuPlacement.publish(ctx)
	status := publishedPools(t, pub)

	dedicated := poolOfKind(t, status, types.CPUPoolKindDedicated)
	if !reflect.DeepEqual(dedicated.CPUs, []uint32{0, 4}) {
		t.Errorf("dedicated CPUs: want [0 4], got %v", dedicated.CPUs)
	}
	if dedicated.TotalCores != 1 || dedicated.FreeWholeCores != 0 {
		t.Errorf("one whole core is taken: want 1/0 total/free cores, got %d/%d",
			dedicated.TotalCores, dedicated.FreeWholeCores)
	}

	// Six threads are unclaimed, but core 2 is kernel-isolated and is on offer
	// only to a workload that asks for isolation, so it is not free capacity for
	// an ordinary one -- which is the question this pool answers.
	housekeeping := poolOfKind(t, status, types.CPUPoolKindHousekeeping)
	if housekeeping.FreeThreads != 4 || housekeeping.FreeWholeCores != 2 {
		t.Errorf("want 4 free threads on 2 free whole cores, got %d/%d",
			housekeeping.FreeThreads, housekeeping.FreeWholeCores)
	}

	isolated := poolOfKind(t, status, types.CPUPoolKindIsolated)
	if !reflect.DeepEqual(isolated.CPUs, []uint32{2, 6}) {
		t.Errorf("isolated CPUs: want the kernel's set [2 6], got %v", isolated.CPUs)
	}
	if isolated.FreeWholeCores != 1 {
		t.Errorf("core 2 is isolated and untaken, want 1 free whole core, got %d",
			isolated.FreeWholeCores)
	}
}

// The operator writes isolcpus, so a mistake in it is reported where they look
// at the node: as warnings on the isolated pool, and only there, each naming
// its issue and what to change.
func TestPublishCPUPoolStatus_IsolationMistakesAreWarningsOnTheIsolatedPool(t *testing.T) {
	ps := testPubSub(t)
	pub := testPublication(t, ps, types.CPUPoolStatus{})
	// Core 2 is CPUs 2 and 6; isolating only 2 leaves half a core.
	placer := testPlacerIsolating(t, 2)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:     newCPUPlacement(placer),
		pubCPUPoolStatus: pub,
	})

	ctx.cpuPlacement.publish(ctx)
	status := publishedPools(t, pub)

	warnings := poolOfKind(t, status, types.CPUPoolKindIsolated).Warnings
	if len(warnings) != 1 {
		t.Fatalf("want one warning for the half-isolated core, got %+v", warnings)
	}
	e := warnings[0]
	if e.Issue != types.CPUPoolIssuePartialCore ||
		e.ErrorSeverity != types.ErrorSeverityWarning || e.ErrorTime.IsZero() ||
		e.ErrorRetryCondition == "" || !strings.Contains(e.Error, "CPUs [2] but not their SMT siblings [6]") {
		t.Errorf("unexpected warning %+v", e)
	}
	for _, kind := range []types.CPUPoolKind{types.CPUPoolKindHousekeeping, types.CPUPoolKindDedicated} {
		if warnings := poolOfKind(t, status, kind).Warnings; len(warnings) != 0 {
			t.Errorf("the %s pool is not defined by isolcpus, got warnings %+v", kind, warnings)
		}
	}
}

// Each kind of mistake is its own issue.
func TestIsolationWarnings_IssuePerKind(t *testing.T) {
	warnings := isolationWarnings([]cpuallocator.IsolationIssue{
		{Kind: cpuallocator.IsolationIssueReservedCPUs, Message: "reserved"},
		{Kind: cpuallocator.IsolationIssuePartialCore, Message: "partial"},
	}, time.Now())
	if len(warnings) != 2 || warnings[0].Issue != types.CPUPoolIssueReservedCPUs ||
		warnings[1].Issue != types.CPUPoolIssuePartialCore {
		t.Errorf("want reserved CPUs then partial core, got %+v", warnings)
	}
	if warnings := isolationWarnings(nil, time.Now()); warnings != nil {
		t.Errorf("no mistakes, want no warnings, got %+v", warnings)
	}
}

// Taking cores away from the shared pool has to move the report with it: a
// stale report would keep promising capacity that is already spoken for.
func TestPublishCPUPoolStatus_FollowsAllocation(t *testing.T) {
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})

	ps := testPubSub(t)
	pub := testPublication(t, ps, types.CPUPoolStatus{})
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		pubCPUPoolStatus:            pub,
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	freeCores := func() uint32 {
		return poolOfKind(t, publishedPools(t, pub),
			types.CPUPoolKindHousekeeping).FreeWholeCores
	}

	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("assignCPUs: %v", err)
	}
	if got := freeCores(); got != 3 {
		t.Errorf("one core was handed out, want 3 free whole cores, got %d", got)
	}

	ctx.cpuPlacement.release(ctx, &status)
	if got := freeCores(); got != 4 {
		t.Errorf("the core was given back, want 4 free whole cores, got %d", got)
	}
}

// Releasing a workload's CPUs must also drop the verdict on the placement they
// were part of, or a stale "needs repack" would be reported for a workload that
// holds nothing.
func TestReleaseCPUs_ClearsCPUPlacement(t *testing.T) {
	ctx := placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(testPlacer(t))})
	status := types.DomainStatus{
		CPUPlacementStatus: types.CPUPlacementStatusRepackAdvised,
	}
	status.VmConfig.CPUs = []uint32{1, 5}

	ctx.cpuPlacement.release(ctx, &status)

	if status.CPUPlacementStatus != types.CPUPlacementStatusUnspecified {
		t.Errorf("want the quality cleared, got %v", status.CPUPlacementStatus)
	}
}
