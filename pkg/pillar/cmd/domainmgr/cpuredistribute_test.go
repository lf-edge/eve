// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
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
	holdCPUs(t, ctx.cpuPlacement.placer, uuid.NewV5(uuid.NamespaceOID, "pinned"),
		2, 3, 6, 7)
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
	status.Placement.Assigned.CPUs = []uint32{1, 5}
	status.VmConfig.CPUs = []uint32{1, 5}
	publishDomainStatus(ctx, &status)

	refreshPlacement(ctx, config.Key())
	if got := publishedCPUs(t, ctx.pubDomainStatus, status.Key()); !reflect.DeepEqual(got, []uint32{1, 5}) {
		t.Errorf("a pinned workload must keep its own CPUs, got %v", got)
	}
}

// The IO threads of a workload under io_placement=housekeeping follow the
// housekeeping set like a shared workload: off the CPUs another workload takes,
// in the cgroup and in the DomainStatus the controller's report comes from.
func TestRefreshPlacement_IOThreadsFollowHousekeeping(t *testing.T) {
	ctx, _ := sharedRefreshContext(t) // another workload holds cores 2 and 3
	config := pinnedConfigForTest("io", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
		IOPlacement: types.CPUIOPlacementHousekeeping,
	})
	config.Activate = true
	ctx.subDomainConfig = testDomainConfigSub(t, testPubSub(t), config)
	holdCPUs(t, ctx.cpuPlacement.placer, config.UUIDandVersion.UUID, 1, 5)
	domain := path.Join(containerd.GetServicesNamespace(), config.GetTaskName())
	cgrouptest.FakeTree(t, map[string]string{
		domain + "/cpuset.cpus":          "1,5,0,2,3,4,6,7",
		domain + "/emulator/cpuset.cpus": "0,2,3,4,6,7",
	})
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion, Activated: true}
	status.DomainName = config.GetTaskName()
	// The IO set from before the other workload took cores 2 and 3.
	status.Placement.Assigned = types.CPUAssignment{CPUs: []uint32{1, 5},
		IOCPUs: []uint32{0, 2, 3, 4, 6, 7}}
	status.VmConfig.CPUs = status.Placement.Assigned.DomainCPUs()
	publishDomainStatus(ctx, &status)

	refreshPlacement(ctx, config.Key())

	item, err := ctx.pubDomainStatus.Get(status.Key())
	if err != nil {
		t.Fatal(err)
	}
	got := item.(types.DomainStatus)
	if want := []uint32{0, 4}; !reflect.DeepEqual(got.Placement.Assigned.IOCPUs, want) {
		t.Errorf("published IO CPUs %v, want %v", got.Placement.Assigned.IOCPUs, want)
	}
	if want := []uint32{1, 5, 0, 4}; !reflect.DeepEqual(got.VmConfig.CPUs, want) {
		t.Errorf("published cpuset %v, want %v", got.VmConfig.CPUs, want)
	}
	for group, want := range map[string]string{domain: "1,5,0,4", domain + "/emulator": "0,4"} {
		b, err := os.ReadFile(cgroup.Path(group, "cpuset.cpus"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != want {
			t.Errorf("%s cpuset.cpus %q, want %q", group, b, want)
		}
	}
}

// A domain about to start again -- a boot retry -- starts on the housekeeping
// set as it is now, not as it was at its first attempt: a shared workload on
// all of it, the IO threads of an io_placement=housekeeping one there, and a
// workload whose IO stays on its own CPUs on those alone.
func TestFollowHousekeeping(t *testing.T) {
	ctx, _ := sharedRefreshContext(t) // another workload holds cores 2 and 3
	stale := []uint32{0, 1, 2, 3, 4, 5, 6, 7}
	for name, tc := range map[string]struct {
		assigned  types.CPUAssignment
		wantCPUs  []uint32
		wantIOCPU []uint32
	}{
		"shared": {types.CPUAssignment{}, []uint32{0, 1, 4, 5}, nil},
		"io_placement=housekeeping": {types.CPUAssignment{CPUs: []uint32{1, 5}, IOCPUs: stale},
			[]uint32{1, 5, 0, 4}, []uint32{0, 4}},
		"io_placement=dedicated": {types.CPUAssignment{CPUs: []uint32{1, 5}},
			[]uint32{1, 5}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.assigned.Holds() {
				holdCPUs(t, ctx.cpuPlacement.placer, uuid.NewV5(uuid.NamespaceOID, name), 1, 5)
				defer ctx.cpuPlacement.placer.Free(uuid.NewV5(uuid.NamespaceOID, name))
			}
			status := types.DomainStatus{}
			status.Placement.Assigned = tc.assigned
			status.VmConfig.CPUs = tc.assigned.DomainCPUs()
			if !tc.assigned.Holds() {
				status.VmConfig.CPUs = stale
			}

			ctx.cpuPlacement.followHousekeeping(&status)

			if !reflect.DeepEqual(status.VmConfig.CPUs, tc.wantCPUs) {
				t.Errorf("CPUs %v, want %v", status.VmConfig.CPUs, tc.wantCPUs)
			}
			if got := status.Placement.Assigned.IOCPUs; !reflect.DeepEqual(got, tc.wantIOCPU) {
				t.Errorf("IO CPUs %v, want %v", got, tc.wantIOCPU)
			}
		})
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
