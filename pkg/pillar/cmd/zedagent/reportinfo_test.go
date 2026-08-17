// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// TestDeviceAPICapabilityCoversCPUPlacement guards the capability gate the
// controller uses to decide whether to offer the CPU placement controls at all.
// The enum is monotonic, so a build that parses and honors the placement fields
// must advertise at least CPU_PLACEMENT_POLICY; anything lower makes the whole
// feature invisible to the controller no matter how well the device implements
// it.
func TestDeviceAPICapabilityCoversCPUPlacement(t *testing.T) {
	want := info.APICapability_API_CAPABILITY_CPU_PLACEMENT_POLICY
	if deviceAPICapability < want {
		t.Errorf("api_capability reported as %s (%d), which is below %s (%d): "+
			"a controller gating on api_capability >= %s will never offer the "+
			"CPU placement fields",
			deviceAPICapability, deviceAPICapability, want, want, want)
	}
}

// TestDeviceAPICapabilityIsDefined catches a value that is numerically higher
// than intended -- e.g. a hand-written integer -- which would claim EdgeDevConfig
// features this build does not implement.
func TestDeviceAPICapabilityIsDefined(t *testing.T) {
	if _, ok := info.APICapability_name[int32(deviceAPICapability)]; !ok {
		t.Errorf("api_capability %d is not a value defined by the vendored eve-api",
			deviceAPICapability)
	}
}

// newCPUPoolTestContext builds a zedagentContext whose subCPUPoolStatus holds
// the given pool report, which is all getCPUPools reads. A nil status leaves the
// subscription empty, i.e. domainmgr has not published a report yet.
func newCPUPoolTestContext(t *testing.T, status *types.CPUPoolStatus) *zedagentContext {
	t.Helper()
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "domainmgr",
		TopicType: types.CPUPoolStatus{},
	})
	if err != nil {
		t.Fatalf("NewPublication(CPUPoolStatus): %v", err)
	}
	if status != nil {
		if err := pub.Publish(status.Key(), *status); err != nil {
			t.Fatalf("Publish(CPUPoolStatus): %v", err)
		}
	}
	// Persistent makes Activate load the published report through the driver, so
	// Get() sees it without pumping the change channel.
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.CPUPoolStatus{},
		Persistent:  true,
	})
	if err != nil {
		t.Fatalf("NewSubscription(CPUPoolStatus): %v", err)
	}
	if err := sub.Activate(); err != nil {
		t.Fatalf("Activate(CPUPoolStatus): %v", err)
	}
	return &zedagentContext{subCPUPoolStatus: sub}
}

// TestGetCPUPools_CopiesEveryFieldToItsOwnProtoField guards the eight hand-copied
// fields of the pool report. A swapped pair -- free for allocated, threads for
// cores -- would still produce a well-formed message, and the controller would
// answer "will this workload fit?" wrongly in the direction that overcommits the
// node. Every value below is distinct so no two fields can be confused.
func TestGetCPUPools_CopiesEveryFieldToItsOwnProtoField(t *testing.T) {
	status := types.CPUPoolStatus{
		Pools: []types.CPUPoolUtilization{
			{
				Kind:             types.CPUPoolKindHousekeeping,
				CPUs:             []uint32{0, 1, 2, 3},
				FreeCPUs:         []uint32{2, 3},
				TotalThreads:     4,
				AllocatedThreads: 1,
				FreeThreads:      3,
				TotalCores:       2,
				FreeWholeCores:   1,
			},
			{
				Kind:             types.CPUPoolKindDedicated,
				CPUs:             []uint32{4, 5, 6, 7, 8, 9},
				FreeCPUs:         []uint32{8, 9},
				TotalThreads:     6,
				AllocatedThreads: 5,
				FreeThreads:      13,
				TotalCores:       11,
				FreeWholeCores:   7,
			},
		},
	}
	ctx := newCPUPoolTestContext(t, &status)

	pools := getCPUPools(ctx)

	if len(pools) != len(status.Pools) {
		t.Fatalf("reported %d pools, want %d", len(pools), len(status.Pools))
	}
	for i, want := range status.Pools {
		got := pools[i]
		if got.Kind != cpuPoolKindToProto(want.Kind) {
			t.Errorf("pool %d kind %v, want %v", i, got.Kind,
				cpuPoolKindToProto(want.Kind))
		}
		assertUint32Slice(t, "cpu_ids", got.CpuIds, want.CPUs)
		assertUint32Slice(t, "free_cpu_ids", got.FreeCpuIds, want.FreeCPUs)
		for _, f := range []struct {
			name      string
			got, want uint32
		}{
			{"total_threads", got.TotalThreads, want.TotalThreads},
			{"allocated_threads", got.AllocatedThreads, want.AllocatedThreads},
			{"free_threads", got.FreeThreads, want.FreeThreads},
			{"total_cores", got.TotalCores, want.TotalCores},
			{"free_whole_cores", got.FreeWholeCores, want.FreeWholeCores},
		} {
			if f.got != f.want {
				t.Errorf("pool %d %s = %d, want %d", i, f.name, f.got, f.want)
			}
		}
	}
}

func assertUint32Slice(t *testing.T, name string, got, want []uint32) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", name, got, want)
			return
		}
	}
}

// TestGetCPUPools_SilentBeforeDomainmgrPublishes covers the ordering that holds
// on every boot: device info is sent before domainmgr has discovered the CPU
// topology. No pools is the correct report then, and it must not panic.
func TestGetCPUPools_SilentBeforeDomainmgrPublishes(t *testing.T) {
	if pools := getCPUPools(newCPUPoolTestContext(t, nil)); pools != nil {
		t.Errorf("reported %v with nothing published, want no pools", pools)
	}
}

// TestCPUPoolKindToProto_CoversEveryKind pins the pool vocabulary onto the wire enum. A kind
// reported under the wrong name tells the controller that CPUs it may not touch
// are free, or the reverse.
func TestCPUPoolKindToProto_CoversEveryKind(t *testing.T) {
	tests := []struct {
		kind types.CPUPoolKind
		want info.CPUPoolKind
	}{
		{types.CPUPoolKindUnspecified, info.CPUPoolKind_CPU_POOL_KIND_UNSPECIFIED},
		{types.CPUPoolKindHousekeeping, info.CPUPoolKind_CPU_POOL_KIND_HOUSEKEEPING},
		{types.CPUPoolKindDedicated, info.CPUPoolKind_CPU_POOL_KIND_DEDICATED},
		{types.CPUPoolKindIsolated, info.CPUPoolKind_CPU_POOL_KIND_ISOLATED},
		// A kind added to types without a mapping here: reported as unspecified
		// (and logged as an error), never as some other pool's kind.
		{types.CPUPoolKind(99), info.CPUPoolKind_CPU_POOL_KIND_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			if got := cpuPoolKindToProto(tt.kind); got != tt.want {
				t.Errorf("cpuPoolKindToProto(%s) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
