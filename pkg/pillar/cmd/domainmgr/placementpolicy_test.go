// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// legacyPinCPU is what zedagent makes of a request that sends only pin_cpu.
var legacyPinCPU = types.CPUPlacementPolicy{}.ResolveLegacy(true, false)

// testTopology is a 4-core SMT2 host, enough for any placement these tests ask
// for: core c is CPUs c and c+4.
func testTopology() *cputopology.Topology {
	var infos []cputopology.CoreInfo
	for thread := uint(0); thread < 2; thread++ {
		for core := uint(0); core < 4; core++ {
			infos = append(infos, cputopology.CoreInfo{LCore: thread*4 + core, CoreID: core})
		}
	}
	return cputopology.BuildTopology(infos)
}

// testPlacer builds a placer over testTopology.
func testPlacer(t *testing.T) *cpuallocator.Placer {
	t.Helper()
	return testPlacerIsolating(t)
}

// testPlacerIsolating is the same four cores on a node booted with isolcpus
// covering the given logical CPUs.
func testPlacerIsolating(t *testing.T, isolated ...uint32) *cpuallocator.Placer {
	t.Helper()
	set := make([]cputopology.LCPU, 0, len(isolated))
	for _, c := range isolated {
		set = append(set, cputopology.LCPU(c))
	}
	placer, err := cpuallocator.NewPlacer(testTopology(), 0, set)
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
	placer, err := cpuallocator.NewPlacer(cputopology.BuildTopology(infos), 0, nil)
	if err != nil {
		t.Fatalf("NewPlacer: %v", err)
	}
	return placer
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
	config.VmConfig.CPUPlacement = policy
	return config
}

// A hypervisor that cannot pin individual vCPUs must refuse a whole-core
// request outright. Every hypervisor that reports CPUPinning gets this far, but
// only kvm turns the reservation into per-vCPU pinning and a guest SMT
// topology; accepting it elsewhere reports the workload as optimally placed
// while nothing was pinned at all.
func TestAssignCPUs_WholeCoreRejectedWithoutTopologyPinning(t *testing.T) {
	ctx := placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(testPlacer(t)), cpuTopologyPinningSupported: false})
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	var status types.DomainStatus

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	if err == nil {
		t.Fatal("whole-core placement must be refused when it cannot be applied")
	}
	var perr *placementError
	if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusTopologyUnsupported {
		t.Fatalf("expected %q, got %v", types.CPUPlacementStatusTopologyUnsupported, err)
	}
	if len(status.VmConfig.CPUs) != 0 || len(status.OrderedCPUs) != 0 {
		t.Errorf("a refused placement must not reserve CPUs, got %v/%v",
			status.VmConfig.CPUs, status.OrderedCPUs)
	}
	if status.CPUPlacementStatus != types.CPUPlacementStatusUnspecified {
		t.Errorf("a refused placement must not be reported as placed, got %v",
			status.CPUPlacementStatus)
	}
}

// Thread-granular pinning needs only a cpuset, so it must keep working on a
// hypervisor without per-vCPU pinning.
func TestAssignCPUs_ThreadGranularPinningStillWorks(t *testing.T) {
	ctx := placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(testPlacer(t)), cpuTopologyPinningSupported: false})
	config := pinnedConfigForTest("threadgranular", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated,
		Pinned: true,
	})
	var status types.DomainStatus

	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("dedicated without full-pcpus-only must still be placed: %v", err)
	}
	if len(status.VmConfig.CPUs) != config.VCpus {
		t.Errorf("want %d CPUs assigned, got %v", config.VCpus, status.VmConfig.CPUs)
	}
}

// A pinned workload's vCPUs are pinned 1:1, whether or not it asked for
// whole cores -- an exclusive CPU set with the vCPUs floating inside it is not
// what anyone asking for pinning expects. One host CPU per vCPU, drawn from the
// workload's own CPUs, and no guest topology: CPUs that need not form whole
// cores cannot describe an SMT structure to the guest.
func TestAssignCPUs_PinnedVCPUsArePinnedOneToOne(t *testing.T) {
	ps := testPubSub(t)
	threadGranular := pinnedConfigForTest("threadgranular", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated,
		Pinned: true,
	})
	legacy := pinnedConfigForTest("legacy", legacyPinCPU)

	for name, tc := range map[string]struct {
		config types.DomainConfig
		ctx    *domainContext
	}{
		// No plan: the CPUs come from the free ones.
		"thread-granular, unplanned": {threadGranular, placementContext(t, &domainContext{cpuPlacement: newCPUPlacement(testPlacer(t))})},
		// A plan: the CPUs are the planned ones.
		"legacy pin_cpu, planned": {legacy, placementContext(t, &domainContext{
			cpuPlacement:    newCPUPlacement(testPlacer(t)),
			pubDomainStatus: testPublication(t, ps, types.DomainStatus{}),
			subDomainConfig: testDomainConfigSub(t, ps, legacy),
		})},
	} {
		t.Run(name, func(t *testing.T) {
			config := tc.config
			var status types.DomainStatus
			if err := tc.ctx.cpuPlacement.assign(tc.ctx, &config, &status); err != nil {
				t.Fatalf("placement failed: %v", err)
			}
			if len(status.OrderedCPUs) != config.VCpus {
				t.Fatalf("want one host CPU per vCPU (%d), got OrderedCPUs %v",
					config.VCpus, status.OrderedCPUs)
			}
			if !equalCPUSets(status.OrderedCPUs, status.VmConfig.CPUs) {
				t.Errorf("the vCPUs must be pinned to the workload's own CPUs %v, got %v",
					status.VmConfig.CPUs, status.OrderedCPUs)
			}
			if status.VMTopology.IsSet() {
				t.Errorf("no guest topology for CPUs that need not be whole cores, got %+v",
					status.VMTopology)
			}
		})
	}
}

// runningConfig is the DomainConfig of a running workload.
func runningConfig(demand types.AppCPUDemand) types.DomainConfig {
	config := pinnedConfigForTest(demand.DisplayName, demand.CPUPlacement)
	config.VmConfig.VCpus = demand.VCpus
	config.Activate = true
	return config
}

// startThreadGranularApp puts a thread-granular workload on the node the way it
// would have landed when it was the only workload there: lowest CPUs first, one
// thread per core, leaving every core it touches half-held and unusable for a
// whole-core request.
//
// It goes through the allocator rather than through assign on purpose: a
// workload the current plan accounts for takes its planned CPUs, so it cannot
// fragment the node. What can is a workload already running on CPUs the plan --
// computed later, over a larger set -- would not have chosen for it. A running
// workload cannot be moved, which is why the remedy is a repack.
func startThreadGranularApp(t *testing.T, ctx *domainContext,
	demand types.AppCPUDemand) {
	t.Helper()
	res := ctx.cpuPlacement.placer.Allocate(cpuallocator.Request{
		UUID: demand.UUID, NumVCPUs: demand.VCpus, Mode: cpuallocator.ModeShared,
	})
	if res.Status != cpuallocator.Success {
		t.Fatalf("thread-granular placement must succeed: %s", res.Message)
	}
	ctx.cpuPlacement.inputsChanged(ctx)
}

// A workload that does not fit among the free CPUs but does fit in the plan is
// blocked only by where the running workloads sit, and restarting them to repack
// is the controller's remedy. Reporting it as "insufficient" -- as the fallback
// path did, by never consulting the plan -- hides the one situation the repack
// code exists for.
func TestAssignCPUs_RepackableShortageReportsNeedsRepack(t *testing.T) {

	// Four threads on a 4-core SMT host, one per core: four threads stay idle
	// but not a single whole core is left.
	//
	fragmenter := threadGranularDemand("thread-granular", 4)
	wholeCore := wholeCoreDemand("wholecore", 2)

	ps := testPubSub(t)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subCPUDemandSet:             testCPUDemandSub(t, ps, fragmenter, wholeCore),
		subDomainConfig:             testDomainConfigSub(t, ps, runningConfig(fragmenter)),
		cpuTopologyPinningSupported: true,
	})
	startThreadGranularApp(t, ctx, fragmenter)

	config := pinnedConfigForTest(wholeCore.DisplayName, wholeCore.CPUPlacement)
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	if err == nil {
		t.Fatalf("no whole core is free, placement must fail; got cpus=%v",
			status.VmConfig.CPUs)
	}
	var perr *placementError
	if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusNeedsRepack {
		t.Fatalf("a workload that the plan does place must be reported as "+
			"repackable, want %q, got %v", types.CPUPlacementStatusNeedsRepack, err)
	}
	// The operator has to be able to see what a repack would achieve.
	if !strings.Contains(perr.Msg, "[0 4]") {
		t.Errorf("the message must name the planned CPUs, got %q", perr.Msg)
	}
	// And who is standing on them: nothing restarts workloads by itself, so
	// "a repack would help" is only actionable with a name attached.
	condition := retryConditionOf(t, err)
	if !strings.Contains(condition, fragmenter.DisplayName) {
		t.Errorf("the retry condition must name the workload holding the planned "+
			"CPUs (%s), got %q", fragmenter.DisplayName, condition)
	}
	if len(status.VmConfig.CPUs) != 0 || len(status.OrderedCPUs) != 0 {
		t.Errorf("a failed placement must not reserve CPUs, got %v/%v",
			status.VmConfig.CPUs, status.OrderedCPUs)
	}
	if status.CPUPlacementStatus != types.CPUPlacementStatusUnspecified {
		t.Errorf("a workload that never started has no placement verdict, got %v",
			status.CPUPlacementStatus)
	}
}

// The same fragmented node, but a request no arrangement of workloads could
// satisfy. Here "insufficient" is the honest answer, and the allocator's
// shortage explanation must survive.
func TestAssignCPUs_UnfittableRequestStaysInsufficient(t *testing.T) {

	fragmenter := threadGranularDemand("thread-granular", 4)
	// Five whole cores on a four-core host: unplaceable even on an empty node.
	tooBig := wholeCoreDemand("toobig", 10)

	ps := testPubSub(t)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subCPUDemandSet:             testCPUDemandSub(t, ps, fragmenter, tooBig),
		subDomainConfig:             testDomainConfigSub(t, ps),
		cpuTopologyPinningSupported: true,
	})
	startThreadGranularApp(t, ctx, fragmenter)

	config := pinnedConfigForTest(tooBig.DisplayName, tooBig.CPUPlacement)
	config.VmConfig.VCpus = tooBig.VCpus
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusInsufficient {
		t.Fatalf("a request the plan cannot place either must stay unsatisfiable, "+
			"want %q, got %v", types.CPUPlacementStatusInsufficient, err)
	}
	if !strings.Contains(perr.Msg, "need 5 free cores") {
		t.Errorf("the shortage explanation must be kept, got %q", perr.Msg)
	}
	// The condition a controller waits on has to carry the same counts as the
	// message, taken from the allocator rather than recomputed, so the two can
	// never disagree about how short the node is.
	condition := retryConditionOf(t, err)
	for _, want := range []string{"5 whole physical cores", "0 free now"} {
		if !strings.Contains(condition, want) {
			t.Errorf("the retry condition must state the shortage (%q), got %q",
				want, condition)
		}
	}
	if status.CPUPlacementStatus != types.CPUPlacementStatusUnspecified {
		t.Errorf("a workload that never started has no placement verdict, got %v",
			status.CPUPlacementStatus)
	}
}

// SMT switched off in the platform firmware is the likeliest way a whole-core
// request fails, and it is not a malformed policy: nothing about the workload's
// config is wrong, and no amount of freeing CPUs helps. The allocator reports it
// as an InvalidRequest, which maps to an invalid policy and sends the operator
// auditing a config that is correct; the TopologyUnsupported flag is what says
// the node, not the request, is the problem.
func TestAssignCPUs_SMTDisabledReportsTopologyUnsupported(t *testing.T) {

	ps := testPubSub(t)
	config := pinnedConfigForTest("wholecore", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	})
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacerNoSMT(t)),
		subDomainConfig:             testDomainConfigSub(t, ps, config),
		cpuTopologyPinningSupported: true,
	})
	var status types.DomainStatus
	status.UUIDandVersion = config.UUIDandVersion

	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	var perr *placementError
	if !errors.As(err, &perr) ||
		perr.Status != types.CPUPlacementStatusTopologyUnsupported {
		t.Fatalf("an SMT-less node must report %q, got %v",
			types.CPUPlacementStatusTopologyUnsupported, err)
	}
	if !strings.Contains(perr.Msg, "SMT is disabled") {
		t.Errorf("the message must say why no core qualifies, got %q", perr.Msg)
	}
	// Neither of the generic remedies for this code applies here: the hypervisor
	// can pin, and there is nothing to free. Only firmware or threads_per_core=1.
	condition := retryConditionOf(t, err)
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
		want types.CPUPlacementStatus
	}{
		{"shortage the plan can place", cpuallocator.Insufficient, planned,
			types.CPUPlacementStatusNeedsRepack},
		{"shortage the plan cannot place", cpuallocator.Insufficient, unplanned,
			types.CPUPlacementStatusInsufficient},
		// An absent entry is a zero Result, whose Status happens to be Success.
		{"workload not in the plan at all", cpuallocator.Insufficient, nil,
			types.CPUPlacementStatusInsufficient},
		{"NUMA constraint the plan can meet", cpuallocator.NeedsRebalance, planned,
			types.CPUPlacementStatusNeedsRepack},
		{"NUMA constraint, unplanned", cpuallocator.NeedsRebalance, nil,
			types.CPUPlacementStatusNeedsRepack},
		{"NUMA constraint the plan cannot meet", cpuallocator.NeedsRebalance, unplanned,
			types.CPUPlacementStatusInsufficient},
		// A caller bug must not be reported as something a repack would fix.
		{"invalid request", cpuallocator.InvalidRequest, planned,
			types.CPUPlacementStatusPolicyInvalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := liveAllocationError("app", id,
				cpuallocator.Result{Status: tt.live, Message: "no room"}, tt.plan, nil, nil)
			if err.Status != tt.want {
				t.Errorf("status = %q, want %q (%s)", err.Status, tt.want, err.Msg)
			}
			// Whatever the classification, the report has to say what would
			// change it: the device never re-attempts placement, so an empty
			// condition leaves a controller waiting for a recovery that will
			// not come.
			condition := retryConditionOf(t, err)
			if condition == "" {
				t.Errorf("%s must carry a retry condition", err.Status)
			}
			if !strings.Contains(condition, "does not re-attempt") {
				t.Errorf("the condition must not imply the device retries: %q", condition)
			}
		})
	}
}

// Every refusal this path can publish must come with a retry condition, and
// one that names the action for that specific refusal. An "insufficient" with
// an empty retry_condition is what the controller cannot act on.
func TestRefuseCPUs_RetryConditionPerStatus(t *testing.T) {
	for _, tt := range []struct {
		status types.CPUPlacementStatus
		// want is a phrase specific to this refusal's remedy, so a table that
		// collapsed every refusal onto one generic sentence would fail here.
		want string
	}{
		{types.CPUPlacementStatusInsufficient, "Stop another pinned workload"},
		{types.CPUPlacementStatusNeedsRepack, "Restart the pinned workloads together"},
		{types.CPUPlacementStatusOddVCPU, "even number"},
		{types.CPUPlacementStatusIsolationUnavailable, "isolcpus"},
		{types.CPUPlacementStatusTopologyUnsupported, "full_pcpus_only"},
		{types.CPUPlacementStatusPolicyInvalid, "CPU placement policy"},
	} {
		t.Run(tt.status.String(), func(t *testing.T) {
			err := placementErrorf(tt.status, "something specific went wrong")
			var status types.DomainStatus
			refuseCPUs(&status, err)
			if status.CPUPlacementStatus != tt.status {
				t.Errorf("verdict = %q, want %q", status.CPUPlacementStatus, tt.status)
			}
			condition := status.ErrorRetryCondition
			if condition == "" {
				t.Fatalf("%s published with an empty retry condition", tt.status)
			}
			if !strings.Contains(condition, tt.want) {
				t.Errorf("condition for %s must mention %q, got %q",
					tt.status, tt.want, condition)
			}
			// The message and the condition are shown in different places; a
			// condition that just repeats the message says nothing new.
			if strings.Contains(condition, err.Msg) {
				t.Errorf("condition must not repeat the message: %q", condition)
			}
			// Nothing on the device brings the workload back by itself, so the
			// condition must not let a reader assume it will.
			if !strings.Contains(condition, "does not re-attempt") {
				t.Errorf("condition for %s must say placement is not re-attempted, got %q",
					tt.status, condition)
			}
		})
	}
}

// The retry condition is only useful if it survives the trip to the wire, where
// it is a field of its own next to the description.
func TestRefuseCPUs_RetryConditionReachesErrorInfo(t *testing.T) {
	err := placementErrorf(types.CPUPlacementStatusInsufficient,
		"topology pinning for app: need 5 free cores, have 4")

	var status types.DomainStatus
	refuseCPUs(&status, err)
	errInfo := status.ToProto()
	if errInfo == nil {
		t.Fatal("a placement failure must produce an ErrorInfo")
	}
	if errInfo.Description != err.Msg {
		t.Errorf("description = %q, want %q", errInfo.Description, err.Msg)
	}
	if errInfo.RetryCondition == "" {
		t.Error("retry_condition reached the controller empty")
	}
	if errInfo.RetryCondition != status.ErrorRetryCondition {
		t.Errorf("retry_condition = %q, want %q", errInfo.RetryCondition,
			status.ErrorRetryCondition)
	}
}

// retryConditionOf is the retry condition refuseCPUs reports for a refusal.
func retryConditionOf(t *testing.T, err error) string {
	t.Helper()
	var refusal *placementError
	if !errors.As(err, &refusal) {
		t.Fatalf("not a placement refusal: %v", err)
	}
	return refusal.retryCondition()
}

// The live allocator says a repack would fit a NUMA-local request, but the
// plan -- every configured workload, from an empty slate -- has no slot for it.
// No repack can help then, so neither the code nor the retry condition may
// suggest one.
func TestLiveAllocationError_NoPlannedSlotIsNotARepack(t *testing.T) {
	id := uuid.NewV5(uuid.NamespaceOID, "no-planned-slot")
	plan := map[uuid.UUID]cpuallocator.Result{
		id: {Status: cpuallocator.Insufficient, Message: "need 4 cores in one NUMA node"},
	}
	err := liveAllocationError("app", id, cpuallocator.Result{
		Status:      cpuallocator.NeedsRebalance,
		Message:     "need 4 cores in one NUMA node; none has enough (total free 6)",
		CoresNeeded: 4,
		CoresFree:   6,
	}, plan, nil, nil)
	if err.Status != types.CPUPlacementStatusInsufficient {
		t.Errorf("code = %q, want %q (%s)", err.Status,
			types.CPUPlacementStatusInsufficient, err.Msg)
	}
	if condition := retryConditionOf(t, err); strings.Contains(condition, "repack") {
		t.Errorf("no repack can place it, the condition must not suggest one: %q", condition)
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
		fits, []string{"noisy-a", "noisy-b"}, nil)
	condition := retryConditionOf(t, repack)
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
	}, nil, nil, nil)
	condition = retryConditionOf(t, shortage)
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
	}, nil, nil, nil)
	condition = retryConditionOf(t, numa)
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

	fragmenter := threadGranularDemand("thread-granular", 4)
	wholeCore := wholeCoreDemand("wholecore", 2)

	ps := testPubSub(t)
	statusPub := testPublication(t, ps, types.DomainStatus{})
	config := pinnedConfigForTest(wholeCore.DisplayName, wholeCore.CPUPlacement)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		pubDomainStatus:             statusPub,
		subCPUDemandSet:             testCPUDemandSub(t, ps, fragmenter, wholeCore),
		subDomainConfig:             testDomainConfigSub(t, ps, config, runningConfig(fragmenter)),
		cpuPinningSupported:         true,
		cpuTopologyPinningSupported: true,
	})
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
	if status.CPUPlacementStatus != types.CPUPlacementStatusNeedsRepack {
		t.Errorf("verdict = %q, want %q", status.CPUPlacementStatus,
			types.CPUPlacementStatusNeedsRepack)
	}

	// Neither retry flag is set, which is what keeps maybeRetryBoot and
	// maybeRetryConfig from picking the workload up on the 30s tick.
	if status.BootFailed || status.ConfigFailed {
		t.Errorf("a placement failure must not schedule an automatic retry, "+
			"BootFailed=%t ConfigFailed=%t", status.BootFailed, status.ConfigFailed)
	}

	// The wakeup on a change to the placement state must not place it either.
	ctx.cpuPlacement.placer.Free(fragmenter.UUID)
	ctx.cpuPlacement.inputsChanged(ctx)
	refreshPlacement(ctx, config.Key())
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
				Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
			},
			wantMode: cpuallocator.ModeWholeCoreSMT,
		},
		{
			name: "threads_per_core=2 is whole-core-smt",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true, ThreadsPerCore: 2,
			},
			wantMode: cpuallocator.ModeWholeCoreSMT,
		},
		{
			name: "threads_per_core=1 parks the sibling",
			policy: types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true, ThreadsPerCore: 1,
			},
			wantMode: cpuallocator.ModeOnePerCore,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePlacement(tt.policy, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Mode == cpuallocator.ModeShared {
				t.Fatal("expected whole-core placement")
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
		{types.CPUNUMAPolicySingleNode, cpuallocator.NUMALocal},
	}
	for _, tt := range tests {
		t.Run(tt.in.String(), func(t *testing.T) {
			got, err := resolvePlacement(types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
				NUMAPolicy: tt.in,
			}, false)
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
	got, err := resolvePlacement(types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true,
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Mode != cpuallocator.ModeShared {
		t.Error("dedicated without full-pcpus-only must be thread-granular")
	}
}

func TestResolvePlacement_IOPlacement(t *testing.T) {
	base := types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true}

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
			got, err := resolvePlacement(p, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.IOHousekeeping != tt.want {
				t.Errorf("IOHousekeeping = %v, want %v", got.IOHousekeeping, tt.want)
			}
		})
	}
}

// The isolated policy is served out of the kernel-isolated set, so resolving it
// is a matter of turning it into that constraint. Whether the node has such
// cores is a separate question, answered where the node is in scope -- see
// TestAssignCPUs_HardIsolationRefusedWithoutIsolatedCPUs.
func TestResolvePlacement_IsolatedRequiresIsolatedCores(t *testing.T) {
	placement, err := resolvePlacement(types.CPUPlacementPolicy{
		Policy:        types.CPUPolicyIsolated,
		Pinned:        true,
		FullPCPUsOnly: true,
	}, false)
	if err != nil {
		t.Fatalf("a whole-core isolated request must resolve: %v", err)
	}
	if !placement.RequireIsolated {
		t.Error("the isolated policy must constrain placement to kernel-isolated cores")
	}
}

// Every field keeps its meaning whatever the others say, so a request is served
// as sent or refused as an invalid policy -- never reinterpreted. The table
// is the contract's matrix: the pool, pinning, the workload type, and the fields
// that refine CPUs of the workload's own.
func TestRejectUnservable(t *testing.T) {
	const (
		housekeeping = types.CPUPolicyHousekeeping
		dedicated    = types.CPUPolicyDedicated
		isolated     = types.CPUPolicyIsolated
	)
	tests := []struct {
		name      string
		policy    types.CPUPlacementPolicy
		container bool
		served    bool
	}{
		{"VM, housekeeping", types.CPUPlacementPolicy{Policy: housekeeping}, false, true},
		{"VM, housekeeping, pinned: not implemented",
			types.CPUPlacementPolicy{Policy: housekeeping, Pinned: true}, false, false},
		{"VM, dedicated, pinned", types.CPUPlacementPolicy{Policy: dedicated, Pinned: true}, false, true},
		{"VM, dedicated, whole cores, pinned",
			types.CPUPlacementPolicy{Policy: dedicated, Pinned: true, FullPCPUsOnly: true}, false, true},
		{"VM, dedicated, not pinned: not implemented",
			types.CPUPlacementPolicy{Policy: dedicated, FullPCPUsOnly: true}, false, false},
		{"VM, isolated, whole cores, pinned",
			types.CPUPlacementPolicy{Policy: isolated, Pinned: true, FullPCPUsOnly: true}, false, true},
		{"VM, isolated, one CPU at a time: not implemented",
			types.CPUPlacementPolicy{Policy: isolated, Pinned: true}, false, false},
		{"VM, isolated, not pinned: not implemented",
			types.CPUPlacementPolicy{Policy: isolated, FullPCPUsOnly: true}, false, false},

		{"container, housekeeping", types.CPUPlacementPolicy{Policy: housekeeping}, true, true},
		{"container, housekeeping, pinned: no vCPUs",
			types.CPUPlacementPolicy{Policy: housekeeping, Pinned: true}, true, false},
		{"container, dedicated", types.CPUPlacementPolicy{Policy: dedicated}, true, true},
		{"container, dedicated, pinned: no vCPUs",
			types.CPUPlacementPolicy{Policy: dedicated, Pinned: true}, true, false},
		{"container, isolated, whole cores: the RT container",
			types.CPUPlacementPolicy{Policy: isolated, FullPCPUsOnly: true}, true, true},
		{"container, io_placement: no QEMU threads",
			types.CPUPlacementPolicy{Policy: dedicated, FullPCPUsOnly: true,
				IOPlacement: types.CPUIOPlacementHousekeeping}, true, false},

		{"housekeeping with full_pcpus_only",
			types.CPUPlacementPolicy{Policy: housekeeping, FullPCPUsOnly: true}, false, false},
		{"housekeeping with numa_policy",
			types.CPUPlacementPolicy{Policy: housekeeping, NUMAPolicy: types.CPUNUMAPolicySingleNode}, false, false},
		{"one CPU at a time with numa_policy",
			types.CPUPlacementPolicy{Policy: dedicated, Pinned: true,
				NUMAPolicy: types.CPUNUMAPolicySingleNode}, false, false},
		{"one CPU at a time with io_placement",
			types.CPUPlacementPolicy{Policy: dedicated, Pinned: true,
				IOPlacement: types.CPUIOPlacementHousekeeping}, false, false},
		{"one CPU at a time with threads_per_core",
			types.CPUPlacementPolicy{Policy: dedicated, Pinned: true, ThreadsPerCore: 1}, false, false},
		{"whole cores with threads_per_core out of range",
			types.CPUPlacementPolicy{Policy: dedicated, Pinned: true, FullPCPUsOnly: true,
				ThreadsPerCore: 3}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolvePlacement(tt.policy, tt.container)
			if tt.served {
				if err != nil {
					t.Fatalf("want served, got %v", err)
				}
				return
			}
			var perr *placementError
			if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusPolicyInvalid {
				t.Fatalf("want %q, got %v", types.CPUPlacementStatusPolicyInvalid, err)
			}
		})
	}
}

// whole-core-smt draws two vCPUs from every physical core, so an odd count can
// never be satisfied. The controller validates this too, but the device keeps a
// backstop so a hand-written config cannot half-start a VM.
func TestValidateVCPUCount_OddRejectedForWholeCoreSMT(t *testing.T) {
	smt := resolvedPlacement{Mode: cpuallocator.ModeWholeCoreSMT}
	if err := validateVCPUCount(smt, 3); err == nil {
		t.Fatal("odd vCPU count must be rejected for whole-core-smt")
	} else {
		var perr *placementError
		if !errors.As(err, &perr) || perr.Status != types.CPUPlacementStatusOddVCPU {
			t.Errorf("expected %q, got %v", types.CPUPlacementStatusOddVCPU, err)
		}
	}
	if err := validateVCPUCount(smt, 4); err != nil {
		t.Errorf("even count must be accepted: %v", err)
	}
	// one-per-core has no parity constraint.
	ope := resolvedPlacement{Mode: cpuallocator.ModeOnePerCore}
	if err := validateVCPUCount(ope, 3); err != nil {
		t.Errorf("one-per-core must accept an odd count: %v", err)
	}
}
