// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// The cpuset a non-pinned workload is actually confined to is rewritten in the
// cgroup, but the record of it lives in DomainStatus -- which is what the rest
// of the device, and through zedagent the controller, reads. Without a publish
// the two drift apart: the workload is observed on two CPUs while EVE reports
// six.
func TestUpdateNonPinnedCPUs_PublishesTheEnforcedSet(t *testing.T) {
	ps := testPubSub(t)
	pub := testPublication(t, ps, types.DomainStatus{})
	ctx := &domainContext{placer: testPlacer(t), pubDomainStatus: pub}
	// testPlacer numbers the siblings of core c as CPU c and CPU c+4, so this
	// takes cores 2 and 3 away from the shared pool.
	ctx.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "pinned"),
		[]uint32{2, 3, 6, 7})

	config := sharedConfigForTest("besteffort")
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion}
	status.DomainName = config.DisplayName
	// The set from before the pinned workload arrived.
	status.VmConfig.CPUs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}
	if err := pub.Publish(status.Key(), status); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if err := updateNonPinnedCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("updateNonPinnedCPUs: %v", err)
	}

	want := []uint32{0, 1, 4, 5}
	if got := publishedCPUs(t, pub, status.Key()); !reflect.DeepEqual(got, want) {
		t.Errorf("published CPUs %v, want %v -- the record must describe the "+
			"cpuset that is enforced, not the one from activation time", got, want)
	}
}

// A wakeup that arrives when the workload cannot be updated -- here, before it
// has a DomainStatus at all -- must leave the change pending rather than
// consume it. Nothing sends a second wakeup for a change that already happened,
// so a swallowed one leaves the workload spread across cores another workload
// now owns.
func TestRedistributeNonPinnedCPUs_UnappliedChangeStaysPending(t *testing.T) {
	isolatePinningOverride(t)
	ps := testPubSub(t)
	statusPub := testPublication(t, ps, types.DomainStatus{})
	config := sharedConfigForTest("besteffort")
	ctx := &domainContext{
		placer:              testPlacer(t),
		pubDomainStatus:     statusPub,
		subDomainConfig:     testDomainConfigSub(t, ps, config),
		cpuPinningSupported: true,
	}
	ctx.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "pinned"),
		[]uint32{2, 3, 6, 7})

	applied := cpuAllocationGen.Load()
	triggerCPUNotification()

	// No DomainStatus yet: there is nothing to update, and the change must not
	// be marked as applied.
	if got := redistributeNonPinnedCPUs(ctx, config.Key(), applied); got != applied {
		t.Fatalf("an un-applied change must stay pending, generation moved to %d", got)
	}

	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion}
	status.DomainName = config.DisplayName
	status.VmConfig.CPUs = []uint32{0, 1, 2, 3, 4, 5, 6, 7}
	if err := statusPub.Publish(status.Key(), status); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// The catch-up pass has to do the work with no new wakeup.
	nowApplied := redistributeNonPinnedCPUs(ctx, config.Key(), applied)
	if nowApplied == applied {
		t.Fatal("the pending change was never applied")
	}
	want := []uint32{0, 1, 4, 5}
	if got := publishedCPUs(t, statusPub, status.Key()); !reflect.DeepEqual(got, want) {
		t.Errorf("cpuset %v, want %v", got, want)
	}

	// And with nothing left pending it must not churn the cgroup on every tick.
	if got := redistributeNonPinnedCPUs(ctx, config.Key(), nowApplied); got != nowApplied {
		t.Errorf("nothing changed, generation should stay at %d, got %d",
			nowApplied, got)
	}
}

// A pinned workload keeps the CPUs it was given, so a redistribution wakeup is
// nothing for it to do -- but it must still count as handled, or every timer
// tick would retry it forever.
func TestRedistributeNonPinnedCPUs_PinnedWorkloadUntouched(t *testing.T) {
	isolatePinningOverride(t)
	ps := testPubSub(t)
	statusPub := testPublication(t, ps, types.DomainStatus{})
	config := pinnedConfigForTest("pinned", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	ctx := &domainContext{
		placer:              testPlacer(t),
		pubDomainStatus:     statusPub,
		subDomainConfig:     testDomainConfigSub(t, ps, config),
		cpuPinningSupported: true,
	}
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion}
	status.DomainName = config.DisplayName
	status.VmConfig.CPUs = []uint32{1, 5}
	if err := statusPub.Publish(status.Key(), status); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	applied := cpuAllocationGen.Load()
	triggerCPUNotification()
	current := cpuAllocationGen.Load()

	if got := redistributeNonPinnedCPUs(ctx, config.Key(), applied); got != current {
		t.Errorf("a pinned workload has nothing pending, want generation %d, got %d",
			current, got)
	}
	if got := publishedCPUs(t, statusPub, status.Key()); !reflect.DeepEqual(got, []uint32{1, 5}) {
		t.Errorf("a pinned workload must keep its own CPUs, got %v", got)
	}
}

// Coalescing the wakeups is fine; losing the fact that something changed is
// not. Two changes in a row leave only one wakeup queued, so the generation is
// what has to carry the second one.
func TestTriggerCPUNotification_CoalescedWakeupStillCounts(t *testing.T) {
	handlersInit()
	defer handlersInit()
	cpuChannel := make(chan Notify, 1)
	handlerMap["domain"] = channels{
		configChannel: make(chan Notify, 1),
		cpuChannel:    cpuChannel,
	}

	before := cpuAllocationGen.Load()
	triggerCPUNotification()
	triggerCPUNotification()

	if len(cpuChannel) != 1 {
		t.Errorf("want the second wakeup coalesced into the queued one, got %d queued",
			len(cpuChannel))
	}
	if got := cpuAllocationGen.Load(); got != before+2 {
		t.Errorf("both changes must be counted even though one wakeup was "+
			"dropped: generation %d, want %d", got, before+2)
	}
}
