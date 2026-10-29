// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// sharedRefreshContext is a node with cores 2 and 3 held by a pinned workload
// (testPlacer numbers the siblings of core c as CPU c and CPU c+4) and one
// shared workload configured.
func sharedRefreshContext(t *testing.T) (*domainContext, types.DomainConfig) {
	t.Helper()
	ps := testPubSub(t)
	config := sharedConfigForTest("besteffort")
	config.Activate = true
	ctx := placementContext(t, &domainContext{
		cpuPlacement:        newCPUPlacement(testPlacer(t)),
		pubDomainStatus:     testPublication(t, ps, types.DomainStatus{}),
		subDomainConfig:     testDomainConfigSub(t, ps, config),
		cpuPinningSupported: true,
	})
	if err := ctx.cpuPlacement.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "pinned"),
		[]uint32{2, 3, 6, 7}); err != nil {
		t.Fatal(err)
	}
	return ctx, config
}

// A running shared workload's cpuset follows the housekeeping set, and the
// record of it in DomainStatus -- which the rest of the device and the
// controller read -- follows the cpuset.
func TestRefreshPlacement_SharedWorkloadFollowsHousekeeping(t *testing.T) {
	ctx, config := sharedRefreshContext(t)
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion, Activated: true}
	status.DomainName = config.DisplayName
	// The set from before the pinned workload arrived.
	status.VmConfig.CPUs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}
	publishDomainStatus(ctx, &status)

	refreshPlacement(ctx, config.Key())

	want := []uint32{0, 1, 4, 5}
	if got := publishedCPUs(t, ctx.pubDomainStatus, status.Key()); !reflect.DeepEqual(got, want) {
		t.Errorf("published CPUs %v, want %v", got, want)
	}
}

// A refresh derives the cpuset from the state as it stands, so one that finds
// nothing to update -- here, no DomainStatus yet -- loses nothing: the next one
// does the work without any new wakeup.
func TestRefreshPlacement_CatchesUpOnTheNextRefresh(t *testing.T) {
	ctx, config := sharedRefreshContext(t)
	refreshPlacement(ctx, config.Key())

	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion, Activated: true}
	status.DomainName = config.DisplayName
	status.VmConfig.CPUs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}
	publishDomainStatus(ctx, &status)

	refreshPlacement(ctx, config.Key())
	want := []uint32{0, 1, 4, 5}
	if got := publishedCPUs(t, ctx.pubDomainStatus, status.Key()); !reflect.DeepEqual(got, want) {
		t.Errorf("cpuset %v, want %v", got, want)
	}
}

// A workload with CPUs of its own keeps them.
func TestRefreshPlacement_PinnedWorkloadKeepsItsCPUs(t *testing.T) {
	ctx, _ := sharedRefreshContext(t)
	config := pinnedConfigForTest("pinned", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	ctx.subDomainConfig = testDomainConfigSub(t, testPubSub(t), config)
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion, Activated: true}
	status.DomainName = config.DisplayName
	status.OrderedCPUs = []uint32{1, 5}
	status.VmConfig.CPUs = []uint32{1, 5}
	publishDomainStatus(ctx, &status)

	refreshPlacement(ctx, config.Key())
	if got := publishedCPUs(t, ctx.pubDomainStatus, status.Key()); !reflect.DeepEqual(got, []uint32{1, 5}) {
		t.Errorf("a pinned workload must keep its own CPUs, got %v", got)
	}
}

// Wakeups coalesce: a handler with one queued does not need a second, since it
// re-derives everything when it runs.
func TestNotifyCPUHandlers_CoalescesWakeups(t *testing.T) {
	handlersInit()
	defer handlersInit()
	cpuChannel := make(chan Notify, 1)
	handlerMap["domain"] = channels{
		configChannel: make(chan Notify, 1),
		cpuChannel:    cpuChannel,
	}
	notifyCPUHandlers()
	notifyCPUHandlers()
	if len(cpuChannel) != 1 {
		t.Errorf("want one wakeup queued, got %d", len(cpuChannel))
	}
}
