// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/localcommand"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// newCPUPoolTestContext builds a zedagentContext whose subCPUPoolStatus holds
// the given pool report, which is all getCPUPools reads. A nil status leaves the
// subscription empty, i.e. domainmgr has not published a report yet.
// A change to the CPU pools must reach the controller when it happens, as a
// change to the assignable adapters does, not with the next periodic report.
func TestCPUPoolStatusChangeTriggersDeviceInfo(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	trigger := make(chan destinationBitset, 1)
	ctx := &zedagentContext{triggerDeviceInfo: trigger}
	ctx.getconfigCtx = &getconfigContext{zedagentCtx: ctx}
	ctx.getconfigCtx.localCmdAgent = localcommand.NewLocalCmdAgent(
		localcommand.ConstructorArgs{Log: log, Watchdog: ps, ConfigAgent: ctx})

	for name, change := range map[string]func(){
		"create": func() { handleCPUPoolStatusCreate(ctx, "global", types.CPUPoolStatus{}) },
		"modify": func() {
			handleCPUPoolStatusModify(ctx, "global", types.CPUPoolStatus{}, types.CPUPoolStatus{})
		},
	} {
		change()
		select {
		case dest := <-trigger:
			if dest&ControllerDest == 0 {
				t.Errorf("%s: the report was triggered, but not towards the controller: %b", name, dest)
			}
		default:
			t.Errorf("%s: no device-info report was triggered", name)
		}
	}
}

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
			{
				Kind: types.CPUPoolKindIsolated,
				CPUs: []uint32{10},
				Warnings: []types.CPUPoolWarning{{
					Issue: types.CPUPoolIssuePartialCore,
					ErrorDescription: types.ErrorDescription{
						Error:               "isolcpus isolates CPUs [10] but not their SMT siblings [11]",
						ErrorTime:           time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
						ErrorSeverity:       types.ErrorSeverityWarning,
						ErrorRetryCondition: "Correct isolcpus and reboot",
					},
				}},
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
		if len(got.Warnings) != len(want.Warnings) {
			t.Errorf("pool %d warnings = %v, want %d", i, got.Warnings, len(want.Warnings))
			continue
		}
		for j, w := range want.Warnings {
			g := got.Warnings[j]
			if g.Issue != info.CPUPoolIssue(w.Issue) || g.Error.GetDescription() != w.Error ||
				g.Error.GetRetryCondition() != w.ErrorRetryCondition ||
				g.Error.GetSeverity() != info.Severity_SEVERITY_WARNING {
				t.Errorf("pool %d warning %d = %v, want %+v", i, j, g, w)
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

// Only a node that can place CPUs advertises it: under EVE-k KubeVirt chooses
// the CPUs, and on an unreadable topology domainmgr places none, so a
// controller gating on the capability must not send them placement fields.
func TestOptionalCapabilities_CPUPlacement(t *testing.T) {
	for _, tt := range []struct {
		name string
		caps *types.Capabilities
		want bool
	}{
		{"a node that can place CPUs", &types.Capabilities{CPUTopologyPinning: true}, true},
		{"a node that pins but cannot place", &types.Capabilities{CPUPinning: true}, false},
		{"capabilities not known yet", nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newCapabilitiesTestContext(t, tt.caps)
			if got := getOptionalCapabilities(ctx).GetCpuPlacement(); got != tt.want {
				t.Errorf("cpu_placement = %v, want %v", got, tt.want)
			}
		})
	}
}

// newCapabilitiesTestContext builds a zedagentContext whose subCapabilities
// holds the given capabilities; nil leaves it empty, as before domainmgr
// publishes them.
func newCapabilitiesTestContext(t *testing.T, caps *types.Capabilities) *zedagentContext {
	t.Helper()
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "domainmgr",
		TopicType: types.Capabilities{},
	})
	if err != nil {
		t.Fatalf("NewPublication(Capabilities): %v", err)
	}
	if caps != nil {
		if err := pub.Publish("global", *caps); err != nil {
			t.Fatalf("Publish(Capabilities): %v", err)
		}
	}
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.Capabilities{},
		Persistent:  true,
	})
	if err != nil {
		t.Fatalf("NewSubscription(Capabilities): %v", err)
	}
	if err := sub.Activate(); err != nil {
		t.Fatalf("Activate(Capabilities): %v", err)
	}
	return &zedagentContext{subCapabilities: sub}
}
