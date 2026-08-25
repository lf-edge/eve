// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// testPlacer builds a placer over a 4-core SMT2 host, enough for any placement
// these tests ask for.
func testPlacer(t *testing.T) *cpuallocator.Placer {
	t.Helper()
	var infos []cputopology.CoreInfo
	for thread := uint(0); thread < 2; thread++ {
		for core := uint(0); core < 4; core++ {
			infos = append(infos, cputopology.CoreInfo{LCore: thread*4 + core, CoreID: core})
		}
	}
	placer, err := cpuallocator.NewPlacer(cputopology.BuildTopology(infos), 0)
	if err != nil {
		t.Fatalf("NewPlacer: %v", err)
	}
	return placer
}

// testPlacerNoSMT is the same four cores with SMT switched off in firmware:
// every core presents a single thread, so no core can ever present threads=2.
func testPlacerNoSMT(t *testing.T) *cpuallocator.Placer {
	t.Helper()
	var infos []cputopology.CoreInfo
	for core := uint(0); core < 4; core++ {
		infos = append(infos, cputopology.CoreInfo{LCore: core, CoreID: core})
	}
	placer, err := cpuallocator.NewPlacer(cputopology.BuildTopology(infos), 0)
	if err != nil {
		t.Fatalf("NewPlacer: %v", err)
	}
	return placer
}

// isolatePinningOverride points the operator-editable /persist override at an
// empty temporary file, so a test neither reads the host's copy nor inherits
// one another test left behind in these package-level paths.
func isolatePinningOverride(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")
}

// testPubSub builds an in-memory pubsub for tests that need real publications.
func testPubSub(t *testing.T) *pubsub.PubSub {
	t.Helper()
	return pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
}

func testPublication(t *testing.T, ps *pubsub.PubSub, topic interface{}) pubsub.Publication {
	t.Helper()
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: topic,
	})
	if err != nil {
		t.Fatalf("NewPublication(%T): %v", topic, err)
	}
	return pub
}

// testDomainConfigSub publishes the given configs as zedmanager would and
// returns a subscription over them, so code that walks the configured set
// (placement planning, cpuset redistribution) has something to walk.
func testDomainConfigSub(t *testing.T, ps *pubsub.PubSub,
	configs ...types.DomainConfig) pubsub.Subscription {
	t.Helper()
	// Persistent on both ends so the subscription populates from what is
	// already published, the way a real subscriber picks up existing config.
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedmanager",
		TopicType:  types.DomainConfig{},
		Persistent: true,
	})
	if err != nil {
		t.Fatalf("NewPublication(DomainConfig): %v", err)
	}
	for _, config := range configs {
		if err := pub.Publish(config.Key(), config); err != nil {
			t.Fatalf("Publish(DomainConfig): %v", err)
		}
	}
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.DomainConfig{},
		Activate:    true,
		Persistent:  true,
	})
	if err != nil {
		t.Fatalf("NewSubscription(DomainConfig): %v", err)
	}
	return sub
}

// sharedConfigForTest is a workload with no CPU placement intent: it runs on
// whatever the pinned workloads have left over, so its cpuset is recomputed
// every time the dedicated set changes.
func sharedConfigForTest(name string) types.DomainConfig {
	var config types.DomainConfig
	config.UUIDandVersion.UUID = uuid.NewV5(uuid.NamespaceOID, name)
	config.DisplayName = name
	config.VmConfig.VCpus = 2
	return config
}

func publishedCPUs(t *testing.T, pub pubsub.Publication, key string) []uint32 {
	t.Helper()
	item, err := pub.Get(key)
	if err != nil {
		t.Fatalf("no DomainStatus published for %s: %v", key, err)
	}
	return item.(types.DomainStatus).VmConfig.CPUs
}

func pinnedConfigForTest(name string, policy types.CPUPlacementPolicy) types.DomainConfig {
	var config types.DomainConfig
	config.UUIDandVersion.UUID = uuid.NewV5(uuid.NamespaceOID, name)
	config.DisplayName = name
	config.VmConfig.VCpus = 2
	config.VmConfig.CPUsPinned = true
	config.VmConfig.CPUPlacement = policy
	return config
}

// A hypervisor that cannot pin individual vCPUs must refuse a whole-core
// request outright. Every hypervisor that reports CPUPinning gets this far, but
// only kvm turns the reservation into per-vCPU pinning and a guest SMT
// topology; accepting it elsewhere reports the workload as optimally placed
// while nothing was pinned at all.
func TestAssignCPUs_WholeCoreRejectedWithoutTopologyPinning(t *testing.T) {
	ctx := &domainContext{placer: testPlacer(t), cpuTopologyPinningSupported: false}
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	var status types.DomainStatus

	err := assignCPUs(ctx, &config, &status)
	if err == nil {
		t.Fatal("whole-core placement must be refused when it cannot be applied")
	}
	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUTopologyUnsupported {
		t.Fatalf("expected %q, got %v", types.ErrorCodeCPUTopologyUnsupported, err)
	}
	if len(status.VmConfig.CPUs) != 0 || len(status.OrderedCPUs) != 0 {
		t.Errorf("a refused placement must not reserve CPUs, got %v/%v",
			status.VmConfig.CPUs, status.OrderedCPUs)
	}
	if status.PlacementQuality != types.CPUPlacementQualityUnspecified {
		t.Errorf("a refused placement must not be reported as placed, got %v",
			status.PlacementQuality)
	}
}

// Thread-granular pinning needs only a cpuset, so it must keep working on a
// hypervisor without per-vCPU pinning.
func TestAssignCPUs_ThreadGranularPinningStillWorks(t *testing.T) {
	ctx := &domainContext{placer: testPlacer(t), cpuTopologyPinningSupported: false}
	config := pinnedConfigForTest("threadgranular", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated,
	})
	var status types.DomainStatus

	if err := assignCPUs(ctx, &config, &status); err != nil {
		t.Fatalf("dedicated without full-pcpus-only must still be placed: %v", err)
	}
	if len(status.VmConfig.CPUs) != config.VCpus {
		t.Errorf("want %d CPUs assigned, got %v", config.VCpus, status.VmConfig.CPUs)
	}
}

// startThreadGranularApp places a thread-granular dedicated workload, which is
// the only workload that can fragment the node: it takes individual threads, so
// every physical core it lands on is left half-owned and coreIsDedicated then
// refuses that core to any whole-core request. Whole-core workloads cannot
// produce this state -- they hand back whole cores when they stop.
// startThreadGranularApp puts a thread-granular workload on the node the way it
// would have landed when it was the only workload there: lowest CPUs first, one
// thread per core.
//
// It goes through the allocator rather than through assignCPUs on purpose. A
// workload the current plan accounts for takes its planned CPUs on both the
// whole-core and the thread-granular path, so it cannot fragment the node; what
// can is a workload already running on CPUs the plan -- computed later, over a
// larger set -- would not have chosen for it. A running workload cannot be moved,
// which is exactly why the remedy is a repack and not a reshuffle.
func startThreadGranularApp(t *testing.T, ctx *domainContext,
	demand types.AppCPUDemand) {
	t.Helper()
	cpus, err := ctx.placer.AllocateShared(demand.UUID, demand.VCpus)
	if err != nil {
		t.Fatalf("thread-granular placement must succeed: %v", err)
	}
	if len(cpus) != demand.VCpus {
		t.Fatalf("want %d threads taken, got %v", demand.VCpus, cpus)
	}
}

// A workload that does not fit among the free CPUs but does fit in the plan is
// blocked only by where the running workloads sit, and restarting them to repack
// is the controller's remedy. Reporting it as "insufficient" -- as the fallback
// path did, by never consulting the plan -- hides the one situation the repack
// code exists for.
func TestAssignCPUs_RepackableShortageReportsNeedsRepack(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	// Four threads on a 4-core SMT host, one per core: four threads stay idle
	// but not a single whole core is left.
	//
	fragmenter := threadGranularDemand("thread-granular", 4)
	wholeCore := wholeCoreDemand("wholecore", 2)

	ps := testPubSub(t)
	ctx := &domainContext{
		placer:                      testPlacer(t),
		subCPUDemandSet:             testCPUDemandSub(t, ps, fragmenter, wholeCore),
		subDomainConfig:             testDomainConfigSub(t, ps),
		cpuTopologyPinningSupported: true,
	}
	startThreadGranularApp(t, ctx, fragmenter)

	config := pinnedConfigForTest(wholeCore.DisplayName, wholeCore.CPUPlacement)
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := assignCPUs(ctx, &config, &status)
	if err == nil {
		t.Fatalf("no whole core is free, placement must fail; got cpus=%v",
			status.VmConfig.CPUs)
	}
	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUPlacementNeedsRepack {
		t.Fatalf("a workload that the plan does place must be reported as "+
			"repackable, want %q, got %v", types.ErrorCodeCPUPlacementNeedsRepack, err)
	}
	// The operator has to be able to see what a repack would achieve.
	if !strings.Contains(perr.Msg, "[0 4]") {
		t.Errorf("the message must name the planned CPUs, got %q", perr.Msg)
	}
	// And who is standing on them: nothing restarts workloads by itself, so
	// "a repack would help" is only actionable with a name attached.
	condition := placementErrorDescription(err).ErrorRetryCondition
	if !strings.Contains(condition, fragmenter.DisplayName) {
		t.Errorf("the retry condition must name the workload holding the planned "+
			"CPUs (%s), got %q", fragmenter.DisplayName, condition)
	}
	if len(status.VmConfig.CPUs) != 0 || len(status.OrderedCPUs) != 0 {
		t.Errorf("a failed placement must not reserve CPUs, got %v/%v",
			status.VmConfig.CPUs, status.OrderedCPUs)
	}
	if status.PlacementQuality != types.CPUPlacementQualityUnspecified {
		t.Errorf("a workload that never started has no placement quality, got %v",
			status.PlacementQuality)
	}
}

// The same fragmented node, but a request no arrangement of workloads could
// satisfy. Here "insufficient" is the honest answer, and the allocator's
// shortage explanation must survive.
func TestAssignCPUs_UnfittableRequestStaysInsufficient(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	fragmenter := threadGranularDemand("thread-granular", 4)
	// Five whole cores on a four-core host: unplaceable even on an empty node.
	tooBig := wholeCoreDemand("toobig", 10)

	ps := testPubSub(t)
	ctx := &domainContext{
		placer:                      testPlacer(t),
		subCPUDemandSet:             testCPUDemandSub(t, ps, fragmenter, tooBig),
		subDomainConfig:             testDomainConfigSub(t, ps),
		cpuTopologyPinningSupported: true,
	}
	startThreadGranularApp(t, ctx, fragmenter)

	config := pinnedConfigForTest(tooBig.DisplayName, tooBig.CPUPlacement)
	config.VmConfig.VCpus = tooBig.VCpus
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := assignCPUs(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUPlacementInsufficient {
		t.Fatalf("a request the plan cannot place either must stay unsatisfiable, "+
			"want %q, got %v", types.ErrorCodeCPUPlacementInsufficient, err)
	}
	if !strings.Contains(perr.Msg, "need 5 free cores") {
		t.Errorf("the shortage explanation must be kept, got %q", perr.Msg)
	}
	// The condition a controller waits on has to carry the same counts as the
	// message, taken from the allocator rather than recomputed, so the two can
	// never disagree about how short the node is.
	condition := placementErrorDescription(err).ErrorRetryCondition
	for _, want := range []string{"5 whole physical cores", "0 free now"} {
		if !strings.Contains(condition, want) {
			t.Errorf("the retry condition must state the shortage (%q), got %q",
				want, condition)
		}
	}
	if status.PlacementQuality != types.CPUPlacementQualityUnspecified {
		t.Errorf("a workload that never started has no placement quality, got %v",
			status.PlacementQuality)
	}
}

// SMT switched off in the platform firmware is the likeliest way a whole-core
// request fails, and it is not a malformed policy: nothing about the workload's
// config is wrong, and no amount of freeing CPUs helps. The allocator reports it
// as an InvalidRequest, which maps to cpu.policy.invalid and sends the operator
// auditing a config that is correct; the TopologyUnsupported flag is what says
// the node, not the request, is the problem.
func TestAssignCPUs_SMTDisabledReportsTopologyUnsupported(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	ps := testPubSub(t)
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	ctx := &domainContext{
		placer:                      testPlacerNoSMT(t),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	}
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := assignCPUs(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) ||
		perr.Code != types.ErrorCodeCPUTopologyUnsupported {
		t.Fatalf("an SMT-less node must report %q, got %v",
			types.ErrorCodeCPUTopologyUnsupported, err)
	}
	if !strings.Contains(perr.Msg, "SMT is disabled") {
		t.Errorf("the message must say why no core qualifies, got %q", perr.Msg)
	}
	// Neither of the generic remedies for this code applies here: the hypervisor
	// can pin, and there is nothing to free. Only firmware or threads_per_core=1.
	condition := placementErrorDescription(err).ErrorRetryCondition
	for _, want := range []string{"SMT", "threads_per_core=1"} {
		if !strings.Contains(condition, want) {
			t.Errorf("the retry condition must name %q, got %q", want, condition)
		}
	}
	if len(status.VmConfig.CPUs) != 0 || len(status.OrderedCPUs) != 0 {
		t.Errorf("a failed placement must not reserve CPUs, got %v/%v",
			status.VmConfig.CPUs, status.OrderedCPUs)
	}
}

// The classification table on its own, including the cases the end-to-end tests
// above cannot reach.
func TestLiveAllocationError_Classification(t *testing.T) {
	id := uuid.NewV5(uuid.NamespaceOID, "classify")
	fits := cpuallocator.Result{
		Status: cpuallocator.Success,
		Assignment: &cpuallocator.Assignment{
			OrderedHostCPUs: []cputopology.LCPU{0, 4},
		},
	}
	planned := map[uuid.UUID]cpuallocator.Result{id: fits}
	unplanned := map[uuid.UUID]cpuallocator.Result{
		id: {Status: cpuallocator.Insufficient, Message: "need 5 free cores, have 4"},
	}

	for _, tt := range []struct {
		name string
		live cpuallocator.Status
		plan map[uuid.UUID]cpuallocator.Result
		want string
	}{
		{"shortage the plan can place", cpuallocator.Insufficient, planned,
			types.ErrorCodeCPUPlacementNeedsRepack},
		{"shortage the plan cannot place", cpuallocator.Insufficient, unplanned,
			types.ErrorCodeCPUPlacementInsufficient},
		// An absent entry is a zero Result, whose Status happens to be Success.
		{"workload not in the plan at all", cpuallocator.Insufficient, nil,
			types.ErrorCodeCPUPlacementInsufficient},
		{"NUMA constraint the plan can meet", cpuallocator.NeedsRebalance, planned,
			types.ErrorCodeCPUPlacementNeedsRepack},
		{"NUMA constraint, unplanned", cpuallocator.NeedsRebalance, nil,
			types.ErrorCodeCPUPlacementNeedsRepack},
		// A caller bug must not be reported as something a repack would fix.
		{"invalid request", cpuallocator.InvalidRequest, planned,
			types.ErrorCodeCPUPolicyInvalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := liveAllocationError("app", id,
				cpuallocator.Result{Status: tt.live, Message: "no room"}, tt.plan, nil)
			if err.Code != tt.want {
				t.Errorf("code = %q, want %q (%s)", err.Code, tt.want, err.Msg)
			}
			// Whatever the classification, the report has to say what would
			// change it: the device never re-attempts placement, so an empty
			// condition leaves a controller waiting for a recovery that will
			// not come.
			condition := placementErrorDescription(err).ErrorRetryCondition
			if condition == "" {
				t.Errorf("%s must carry a retry condition", err.Code)
			}
			if !strings.Contains(condition, "does not re-attempt") {
				t.Errorf("the condition must not imply the device retries: %q", condition)
			}
		})
	}
}

// Every code this path can publish must come with a retry condition, and one
// that names the action for that specific code. A structured "insufficient" with
// an empty retry_condition is what the controller cannot act on.
func TestPlacementErrorDescription_RetryConditionPerCode(t *testing.T) {
	for _, tt := range []struct {
		code string
		// want is a phrase specific to this code's remedy, so a table that
		// collapsed every code onto one generic sentence would fail here.
		want string
	}{
		{types.ErrorCodeCPUPlacementInsufficient, "Stop another pinned workload"},
		{types.ErrorCodeCPUPlacementNeedsRepack, "Restart the pinned workloads together"},
		{types.ErrorCodeCPUPolicyOddVCPU, "even number"},
		{types.ErrorCodeCPUIsolationTierUnavailable, "isolation_tier"},
		{types.ErrorCodeCPUTopologyUnsupported, "full_pcpus_only"},
		{types.ErrorCodeCPUPolicyInvalid, "CPU placement policy"},
	} {
		t.Run(tt.code, func(t *testing.T) {
			err := placementErrorf(tt.code, "something specific went wrong")
			description := placementErrorDescription(err)
			if description.ErrorCode != tt.code {
				t.Errorf("code = %q, want %q", description.ErrorCode, tt.code)
			}
			if description.ErrorRetryCondition == "" {
				t.Fatalf("%s published with an empty retry condition", tt.code)
			}
			if !strings.Contains(description.ErrorRetryCondition, tt.want) {
				t.Errorf("condition for %s must mention %q, got %q",
					tt.code, tt.want, description.ErrorRetryCondition)
			}
			// The message and the condition are shown in different places; a
			// condition that just repeats the message says nothing new.
			if strings.Contains(description.ErrorRetryCondition, err.Msg) {
				t.Errorf("condition must not repeat the message: %q",
					description.ErrorRetryCondition)
			}
			// Nothing on the device brings the workload back by itself, so the
			// condition must not let a reader assume it will.
			if !strings.Contains(description.ErrorRetryCondition, "does not re-attempt") {
				t.Errorf("condition for %s must say placement is not re-attempted, got %q",
					tt.code, description.ErrorRetryCondition)
			}
		})
	}
}

// The retry condition is only useful if it survives the trip to the wire, where
// it is a field of its own next to the code.
func TestPlacementErrorDescription_ReachesErrorInfo(t *testing.T) {
	err := placementErrorf(types.ErrorCodeCPUPlacementInsufficient,
		"topology pinning for app: need 5 free cores, have 4")

	var et types.ErrorAndTime
	et.SetErrorDescription(placementErrorDescription(err))
	errInfo := et.ToProto()
	if errInfo == nil {
		t.Fatal("a placement failure must produce an ErrorInfo")
	}
	if errInfo.ErrorCode != types.ErrorCodeCPUPlacementInsufficient {
		t.Errorf("error_code = %q, want %q", errInfo.ErrorCode,
			types.ErrorCodeCPUPlacementInsufficient)
	}
	if errInfo.RetryCondition == "" {
		t.Error("retry_condition reached the controller empty")
	}
	if errInfo.RetryCondition != et.ErrorRetryCondition {
		t.Errorf("retry_condition = %q, want %q", errInfo.RetryCondition,
			et.ErrorRetryCondition)
	}
}

// A repack is only actionable if the report says which workloads have to be
// restarted, and a shortage only if it says how many cores short the node is.
func TestLiveAllocationError_RetryConditionsAreSpecific(t *testing.T) {
	id := uuid.NewV5(uuid.NamespaceOID, "specific")
	fits := map[uuid.UUID]cpuallocator.Result{id: {
		Status: cpuallocator.Success,
		Assignment: &cpuallocator.Assignment{
			OrderedHostCPUs: []cputopology.LCPU{0, 4},
		},
	}}

	repack := liveAllocationError("app", id,
		cpuallocator.Result{Status: cpuallocator.Insufficient, Message: "no whole core free"},
		fits, []string{"noisy-a", "noisy-b"})
	condition := placementErrorDescription(repack).ErrorRetryCondition
	for _, want := range []string{"noisy-a", "noisy-b", "repack"} {
		if !strings.Contains(condition, want) {
			t.Errorf("repack condition must mention %q, got %q", want, condition)
		}
	}

	shortage := liveAllocationError("app", id, cpuallocator.Result{
		Status:      cpuallocator.Insufficient,
		Message:     "need 5 free cores, have 4",
		CoresNeeded: 5,
		CoresFree:   4,
	}, nil, nil)
	condition = placementErrorDescription(shortage).ErrorRetryCondition
	for _, want := range []string{"5 whole physical cores", "4 free now"} {
		if !strings.Contains(condition, want) {
			t.Errorf("shortage condition must state the counts (%q), got %q",
				want, condition)
		}
	}

	// The same shortage under a single-NUMA-node constraint clears under a
	// different condition, and must say so rather than reuse the flat wording.
	numa := liveAllocationError("app", id, cpuallocator.Result{
		Status:      cpuallocator.NeedsRebalance,
		Message:     "need 2 cores in one NUMA node; none has enough (total free 4)",
		CoresNeeded: 2,
		CoresFree:   4,
	}, nil, nil)
	condition = placementErrorDescription(numa).ErrorRetryCondition
	if !strings.Contains(condition, "single NUMA node") {
		t.Errorf("a NUMA shortage must say the cores have to be on one node, got %q",
			condition)
	}
}

// A CPU-placement failure is not re-attempted by the device. That is EVE's
// established behaviour for a workload whose assigned resource is unavailable --
// an app that cannot get its PCI device is not started later because the device
// came back -- and CPUs follow it. The test pins the semantics so a future change
// towards auto-retry is a deliberate one, and states what the operator gets
// instead: a retry condition that says what to do.
func TestAssignCPUs_PlacementFailureStaysFailedUntilRestarted(t *testing.T) {
	isolatePinningOverride(t)
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")

	fragmenter := threadGranularDemand("thread-granular", 4)
	wholeCore := wholeCoreDemand("wholecore", 2)

	ps := testPubSub(t)
	statusPub := testPublication(t, ps, types.DomainStatus{})
	config := pinnedConfigForTest(wholeCore.DisplayName, wholeCore.CPUPlacement)
	ctx := &domainContext{
		placer:                      testPlacer(t),
		pubDomainStatus:             statusPub,
		subCPUDemandSet:             testCPUDemandSub(t, ps, fragmenter, wholeCore),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuPinningSupported:         true,
		cpuTopologyPinningSupported: true,
	}
	startThreadGranularApp(t, ctx, fragmenter)

	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion
	status.DomainName = config.DisplayName

	// The real activation path, which returns as soon as placement is refused --
	// before any hypervisor work -- and is where the decision not to retry lives.
	config.Activate = true
	doActivate(ctx, config, &status)
	if !status.HasError() {
		t.Fatalf("no whole core is free, activation must fail; got cpus=%v",
			status.VmConfig.CPUs)
	}
	if status.ErrorCode != types.ErrorCodeCPUPlacementNeedsRepack {
		t.Errorf("error code = %q, want %q", status.ErrorCode,
			types.ErrorCodeCPUPlacementNeedsRepack)
	}

	// Neither retry flag is set, which is what keeps maybeRetryBoot and
	// maybeRetryConfig from picking the workload up on the 30s tick.
	if status.BootFailed || status.ConfigFailed {
		t.Errorf("a placement failure must not schedule an automatic retry, "+
			"BootFailed=%t ConfigFailed=%t", status.BootFailed, status.ConfigFailed)
	}

	// The one automatic wakeup domainmgr has for a change in the dedicated CPU
	// set must not place this workload either. It reaches only
	// redistributeNonPinnedCPUs, which leaves anything pinned alone.
	applied := cpuAllocationGen.Load()
	triggerCPUNotification()
	redistributeNonPinnedCPUs(ctx, config.Key(), applied)
	if got := publishedCPUs(t, statusPub, status.Key()); len(got) != 0 {
		t.Errorf("a CPU-set change must not silently place a failed workload, got %v", got)
	}
	item, err := statusPub.Get(status.Key())
	if err != nil {
		t.Fatalf("no DomainStatus published: %v", err)
	}
	published := item.(types.DomainStatus)
	if !published.HasError() {
		t.Error("the failure must stand until the workload is acted on")
	}

	// What the operator gets instead of a retry: the condition to act on.
	if status.ErrorRetryCondition == "" {
		t.Fatal("a failure that never self-heals must say what would fix it")
	}
	if !strings.Contains(status.ErrorRetryCondition, "does not re-attempt") {
		t.Errorf("the report must not let a controller wait for a retry: %q",
			status.ErrorRetryCondition)
	}

	// Deactivation is what clears it. Until then handleModify refuses to
	// activate a workload that HasError(), which is the whole of the "explicit
	// restart" contract.
	status.ClearError()
	if status.HasError() {
		t.Error("deactivation must clear the placement failure")
	}
}

func TestResolvePlacement_ThreadsPerCoreSelectsMode(t *testing.T) {
	tests := []struct {
		name     string
		policy   types.CPUPlacementPolicy
		wantMode cpuallocator.PinMode
	}{
		{
			name: "threads_per_core unset defaults to whole-core-smt",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
			},
			wantMode: cpuallocator.ModeWholeCoreSMT,
		},
		{
			name: "threads_per_core=2 is whole-core-smt",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true, ThreadsPerCore: 2,
			},
			wantMode: cpuallocator.ModeWholeCoreSMT,
		},
		{
			name: "threads_per_core=1 parks the sibling",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true, ThreadsPerCore: 1,
			},
			wantMode: cpuallocator.ModeOnePerCore,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePlacement(tt.policy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.TopologyAware {
				t.Fatal("expected topology-aware placement")
			}
			if got.Mode != tt.wantMode {
				t.Errorf("mode = %v, want %v", got.Mode, tt.wantMode)
			}
		})
	}
}

func TestResolvePlacement_NUMAMapping(t *testing.T) {
	tests := []struct {
		in   types.CPUNUMAPolicy
		want cpuallocator.NUMAPolicy
	}{
		{types.CPUNUMAPolicyUnspecified, cpuallocator.NUMABestEffort},
		{types.CPUNUMAPolicyBestEffort, cpuallocator.NUMABestEffort},
		{types.CPUNUMAPolicyNone, cpuallocator.NUMAAllowCross},
		{types.CPUNUMAPolicyRestricted, cpuallocator.NUMALocal},
		{types.CPUNUMAPolicySingleNode, cpuallocator.NUMALocal},
	}
	for _, tt := range tests {
		t.Run(tt.in.String(), func(t *testing.T) {
			got, err := resolvePlacement(types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true, NUMAPolicy: tt.in,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.NUMA != tt.want {
				t.Errorf("numa = %v, want %v", got.NUMA, tt.want)
			}
		})
	}
}

// Dedicated without full-pcpus-only is thread-granular: it still pins, but via
// the legacy shared-pool allocator, not topology-aware placement.
func TestResolvePlacement_DedicatedWithoutFullPCPUsIsNotTopologyAware(t *testing.T) {
	got, err := resolvePlacement(types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TopologyAware {
		t.Error("dedicated without full-pcpus-only must not be topology-aware")
	}
}

func TestResolvePlacement_IOPlacement(t *testing.T) {
	base := types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true}

	for _, tt := range []struct {
		name string
		io   types.CPUIOPlacement
		want bool
	}{
		{"unspecified defaults to dedicated", types.CPUIOPlacementUnspecified, false},
		{"dedicated", types.CPUIOPlacementDedicated, false},
		{"housekeeping", types.CPUIOPlacementHousekeeping, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := base
			p.IOPlacement = tt.io
			got, err := resolvePlacement(p)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.IOHousekeeping != tt.want {
				t.Errorf("IOHousekeeping = %v, want %v", got.IOHousekeeping, tt.want)
			}
		})
	}
}

// The hard tier needs a kernel command-line change this device cannot make at
// runtime. It must fail closed with a structured code rather than quietly
// running with only soft isolation.
func TestResolvePlacement_HardIsolationFailsClosed(t *testing.T) {
	_, err := resolvePlacement(types.CPUPlacementPolicy{
		Policy:        types.CPUPolicyDedicated,
		FullPCPUsOnly: true,
		IsolationTier: types.CPUIsolationTierHard,
	})
	if err == nil {
		t.Fatal("hard isolation must be rejected")
	}
	var perr *placementError
	if !errors.As(err, &perr) {
		t.Fatalf("expected a placementError carrying an error code, got %T", err)
	}
	if perr.Code != types.ErrorCodeCPUIsolationTierUnavailable {
		t.Errorf("code = %q, want %q", perr.Code, types.ErrorCodeCPUIsolationTierUnavailable)
	}
}

func TestResolvePlacement_SoftAndNoneTiersAccepted(t *testing.T) {
	for _, tier := range []types.CPUIsolationTier{
		types.CPUIsolationTierUnspecified,
		types.CPUIsolationTierNone,
		types.CPUIsolationTierSoft,
	} {
		t.Run(tier.String(), func(t *testing.T) {
			if _, err := resolvePlacement(types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true, IsolationTier: tier,
			}); err != nil {
				t.Errorf("tier %v should be accepted: %v", tier, err)
			}
		})
	}
}

// "protect" asks the node to defer disruptive actions, which nothing on the
// device does. Accepting it silently would hand the controller a guarantee that
// does not exist.
func TestResolvePlacement_ProtectDisruptionFailsClosed(t *testing.T) {
	_, err := resolvePlacement(types.CPUPlacementPolicy{
		Policy:           types.CPUPolicyDedicated,
		FullPCPUsOnly:    true,
		DisruptionPolicy: types.CPUDisruptionPolicyProtect,
	})
	if err == nil {
		t.Fatal("an unimplemented disruption policy must be rejected")
	}
	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUPolicyInvalid {
		t.Fatalf("expected %q, got %v", types.ErrorCodeCPUPolicyInvalid, err)
	}
}

func TestResolvePlacement_AllowAndUnspecifiedDisruptionAccepted(t *testing.T) {
	for _, policy := range []types.CPUDisruptionPolicy{
		types.CPUDisruptionPolicyUnspecified,
		types.CPUDisruptionPolicyAllow,
	} {
		t.Run(policy.String(), func(t *testing.T) {
			if _, err := resolvePlacement(types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
				DisruptionPolicy: policy,
			}); err != nil {
				t.Errorf("disruption policy %v should be accepted: %v", policy, err)
			}
		})
	}
}

// The /persist override is the only way to ask for whole-core placement on a
// device whose controller knows nothing about the policy. Since the override
// cannot set the app config's pin flag, asking for it there must imply pinning
// -- otherwise the file is silently inert, which is what it was.
func TestEffectiveCPUsPinned_PersistOverrideImpliesPinning(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")

	id := uuid.NewV5(uuid.NamespaceOID, "override")
	var config types.DomainConfig
	config.UUIDandVersion.UUID = id
	config.VmConfig.VCpus = 2

	if effectiveCPUsPinned(&config) {
		t.Fatal("no controller policy and no override must not pin")
	}
	writePinningEntryForTest(t, id, &PinningEntry{
		CPUPolicy: "static", PolicyOptions: fullPCPUs(),
	})
	if !effectiveCPUsPinned(&config) {
		t.Error("a whole-core override must imply pinning")
	}

	// The controller stays authoritative whenever it said anything, so a stale
	// local file cannot contradict it.
	config.VmConfig.CPUPlacement.Policy = types.CPUPolicyShared
	if effectiveCPUsPinned(&config) {
		t.Error("an explicit shared policy from the controller must win over the override")
	}
	config.VmConfig.CPUPlacement.Policy = types.CPUPolicyUnspecified

	// An override that does not ask for whole cores keeps the legacy behavior:
	// pinning stays off unless the controller asked for it.
	writePinningEntryForTest(t, id, &PinningEntry{CPUPolicy: "static"})
	if effectiveCPUsPinned(&config) {
		t.Error("static without full-pcpus-only must not imply pinning")
	}
	config.VmConfig.CPUsPinned = true
	if !effectiveCPUsPinned(&config) {
		t.Error("the controller's pin flag must always pin")
	}
}

// End to end through assignCPUs: an override-only workload must take the
// topology path. It is refused here only because this context reports no
// per-vCPU pinning support -- before, it silently fell through to the
// "not pinned" branch and got the whole shared CPU set.
func TestAssignCPUs_PersistOverrideTakesTopologyPath(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")

	id := uuid.NewV5(uuid.NamespaceOID, "override-assign")
	writePinningEntryForTest(t, id, &PinningEntry{
		CPUPolicy: "static", PolicyOptions: fullPCPUs(),
	})
	var config types.DomainConfig
	config.UUIDandVersion.UUID = id
	config.DisplayName = "override-assign"
	config.VmConfig.VCpus = 2

	ctx := &domainContext{placer: testPlacer(t), cpuTopologyPinningSupported: false}
	var status types.DomainStatus
	err := assignCPUs(ctx, &config, &status)

	var perr *placementError
	if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUTopologyUnsupported {
		t.Fatalf("override must be resolved as a whole-core request, got err=%v cpus=%v",
			err, status.VmConfig.CPUs)
	}
	if !status.VmConfig.CPUsPinned {
		t.Error("status must record that the workload is pinned")
	}
}

// whole-core-smt draws two vCPUs from every physical core, so an odd count can
// never be satisfied. The controller validates this too, but the device keeps a
// backstop so a hand-written config cannot half-start a VM.
func TestValidateVCPUCount_OddRejectedForWholeCoreSMT(t *testing.T) {
	smt := resolvedPlacement{TopologyAware: true, Mode: cpuallocator.ModeWholeCoreSMT}
	if err := validateVCPUCount(smt, 3); err == nil {
		t.Fatal("odd vCPU count must be rejected for whole-core-smt")
	} else {
		var perr *placementError
		if !errors.As(err, &perr) || perr.Code != types.ErrorCodeCPUPolicyOddVCPU {
			t.Errorf("expected %q, got %v", types.ErrorCodeCPUPolicyOddVCPU, err)
		}
	}
	if err := validateVCPUCount(smt, 4); err != nil {
		t.Errorf("even count must be accepted: %v", err)
	}
	// one-per-core has no parity constraint.
	ope := resolvedPlacement{TopologyAware: true, Mode: cpuallocator.ModeOnePerCore}
	if err := validateVCPUCount(ope, 3); err != nil {
		t.Errorf("one-per-core must accept an odd count: %v", err)
	}
}
