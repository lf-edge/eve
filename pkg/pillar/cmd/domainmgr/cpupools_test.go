// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
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
	ctx := &domainContext{
		placer:           testPlacer(t),
		pubCPUPoolStatus: pub,
		isolatedCPUs:     []cputopology.LCPU{2, 6},
	}
	// testPlacer numbers the siblings of core c as CPU c and CPU c+4.
	ctx.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "pinned"), []uint32{0, 4})

	publishCPUPoolStatus(ctx)
	status := publishedPools(t, pub)

	dedicated := poolOfKind(t, status, types.CPUPoolKindDedicated)
	if !reflect.DeepEqual(dedicated.CPUs, []uint32{0, 4}) {
		t.Errorf("dedicated CPUs: want [0 4], got %v", dedicated.CPUs)
	}
	if dedicated.TotalCores != 1 || dedicated.FreeWholeCores != 0 {
		t.Errorf("one whole core is taken: want 1/0 total/free cores, got %d/%d",
			dedicated.TotalCores, dedicated.FreeWholeCores)
	}

	housekeeping := poolOfKind(t, status, types.CPUPoolKindHousekeeping)
	if housekeeping.FreeThreads != 6 || housekeeping.FreeWholeCores != 3 {
		t.Errorf("want 6 free threads on 3 free whole cores, got %d/%d",
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

// Taking cores away from the shared pool has to move the report with it: a
// stale report would keep promising capacity that is already spoken for.
func TestPublishCPUPoolStatus_FollowsAllocation(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})

	ps := testPubSub(t)
	pub := testPublication(t, ps, types.CPUPoolStatus{})
	ctx := &domainContext{
		placer:                      testPlacer(t),
		pubCPUPoolStatus:            pub,
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	freeCores := func() uint32 {
		return poolOfKind(t, publishedPools(t, pub),
			types.CPUPoolKindHousekeeping).FreeWholeCores
	}

	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("assignCPUs: %v", err)
	}
	if got := freeCores(); got != 3 {
		t.Errorf("one core was handed out, want 3 free whole cores, got %d", got)
	}

	releaseCPUs(ctx, &status)
	if got := freeCores(); got != 4 {
		t.Errorf("the core was given back, want 4 free whole cores, got %d", got)
	}
}

// Releasing a workload's CPUs must also drop the verdict on the placement they
// were part of, or a stale "needs repack" would be reported for a workload that
// holds nothing.
func TestReleaseCPUs_ClearsPlacementQuality(t *testing.T) {
	ctx := &domainContext{placer: testPlacer(t)}
	status := types.DomainStatus{
		PlacementQuality: types.CPUPlacementQualityNeedsRepack,
	}
	status.VmConfig.CPUs = []uint32{1, 5}

	releaseCPUs(ctx, &status)

	if status.PlacementQuality != types.CPUPlacementQualityUnspecified {
		t.Errorf("want the quality cleared, got %v", status.PlacementQuality)
	}
}
