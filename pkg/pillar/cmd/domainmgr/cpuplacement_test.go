// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// configSubscription is a DomainConfig subscription a test can change between
// steps.
type configSubscription struct {
	mapSubscription
}

func (s *configSubscription) Iterate(f base.StrMapFunc) {
	for key, item := range s.items {
		if !f(key, item) {
			return
		}
	}
}

func newConfigSubscription(configs ...types.DomainConfig) *configSubscription {
	s := &configSubscription{mapSubscription{items: map[string]interface{}{}}}
	for _, config := range configs {
		s.items[config.Key()] = config
	}
	return s
}

// placementContext fills in what placement reads and publishes that the test
// did not set: an empty, complete demand set, no DomainConfigs, a pool report
// publication and a plan file of the test's own.
func placementContext(t *testing.T, ctx *domainContext) *domainContext {
	t.Helper()
	cpuPlanFile = filepath.Join(t.TempDir(), "cpuplan.json")
	if ctx.subCPUDemandSet == nil {
		demands := newConfigSubscription()
		demands.items["global"] = types.CPUDemandSet{Complete: true}
		ctx.subCPUDemandSet = demands
	}
	if ctx.subDomainConfig == nil {
		ctx.subDomainConfig = newConfigSubscription()
	}
	if ctx.pubCPUPoolStatus == nil {
		ctx.pubCPUPoolStatus = testPublication(t, testPubSub(t), types.CPUPoolStatus{})
	}
	return ctx
}

// repackFixture is a node a repack can fix: a thread-granular workload (the
// fragmenter) runs on one thread of every core, so the whole-core workload the
// plan puts on core 0 is refused with needs_repack, and the fragmenter is the
// member that has to move for it.
type repackFixture struct {
	t          *testing.T
	ctx        *domainContext
	configs    *configSubscription
	wholeCore  types.DomainConfig
	fragmenter types.DomainConfig
}

func newRepackFixture(t *testing.T) *repackFixture {
	t.Helper()
	fragmenterDemand := threadGranularDemand("fragmenter", 4)
	wholeCoreDemand := wholeCoreDemand("wholecore", 2)
	fragmenter := pinnedConfigForTest("fragmenter", fragmenterDemand.CPUPlacement)
	fragmenter.VmConfig.VCpus = 4
	fragmenter.Activate = true
	wholeCore := pinnedConfigForTest("wholecore", wholeCoreDemand.CPUPlacement)
	wholeCore.Activate = true
	x := &repackFixture{
		t:          t,
		configs:    newConfigSubscription(fragmenter, wholeCore),
		wholeCore:  wholeCore,
		fragmenter: fragmenter,
	}
	x.ctx = placementContext(t, &domainContext{
		cpuPlacement: newCPUPlacement(testPlacer(t)),
		subCPUDemandSet: testCPUDemandSub(t, testPubSub(t),
			fragmenterDemand, wholeCoreDemand),
		subDomainConfig:             x.configs,
		cpuTopologyPinningSupported: true,
	})
	startThreadGranularApp(t, x.ctx, fragmenterDemand)

	err := x.assign(x.wholeCore)
	var refusal *placementError
	if !errors.As(err, &refusal) || refusal.Status != types.CPUPlacementNeedsRepack {
		t.Fatalf("precondition: want %s, got %v", types.CPUPlacementNeedsRepack, err)
	}
	return x
}

func (x *repackFixture) assign(config types.DomainConfig) error {
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion,
		DisplayName: config.DisplayName}
	return x.ctx.cpuPlacement.assign(x.ctx, &config, &status)
}

// setConfig is a DomainConfig change as the pubsub handler announces it.
func (x *repackFixture) setConfig(config types.DomainConfig) {
	x.configs.items[config.Key()] = config
	x.ctx.cpuPlacement.inputsChanged(x.ctx)
}

// bringDown is the first half of a restart: the config asks for the workload
// to stop, with a new restart counter.
func (x *repackFixture) bringDown(config types.DomainConfig) types.DomainConfig {
	config.Activate = false
	config.RestartCounter++
	x.setConfig(config)
	config.Activate = true
	return config
}

func (x *repackFixture) release(config types.DomainConfig) {
	status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion}
	x.ctx.cpuPlacement.release(x.ctx, &status)
}

func (x *repackFixture) wantWaiting(err error) {
	x.t.Helper()
	var waiting *placementWaiting
	if !errors.As(err, &waiting) || !slices.Equal(waiting.holders, []string{"fragmenter"}) {
		x.t.Fatalf("want a wait for the fragmenter, got %v", err)
	}
}

func (x *repackFixture) wantPlaced(err error, config types.DomainConfig) {
	x.t.Helper()
	if err != nil {
		x.t.Fatalf("%s: want placed, got %v", config.DisplayName, err)
	}
	if !x.ctx.cpuPlacement.placer.Holds(config.UUIDandVersion.UUID) {
		x.t.Fatalf("%s holds no CPUs", config.DisplayName)
	}
}

// The workload a repack is for flags the running workloads in its way, and
// only them.
func TestRepack_FlagsTheWorkloadsInTheWay(t *testing.T) {
	x := newRepackFixture(t)
	id := x.fragmenter.UUIDandVersion.UUID
	if got := x.ctx.cpuPlacement.repackFor(x.ctx, id); !slices.Equal(got, []string{"wholecore"}) {
		t.Errorf("the fragmenter stands on the planned CPUs, want RepackFor [wholecore], got %v", got)
	}
	// A plain stop of the workload the repack is for ends it.
	x.ctx.cpuPlacement.forget(x.ctx, x.wholeCore.UUIDandVersion.UUID)
	if got := x.ctx.cpuPlacement.repackFor(x.ctx, id); got != nil {
		t.Errorf("nothing left to repack for, got RepackFor %v", got)
	}
}

// The controller restarts the flagged set together, but nothing orders the
// configs on their way to domainmgr: the refused workload may come back before
// the member has even been told to stop, while it is stopping, or after it is
// gone. Every order must end with both placed as planned.
func TestRepack_AnyArrivalOrderReachesThePlan(t *testing.T) {
	steps := map[string]func(x *repackFixture){
		"refused workload first": func(x *repackFixture) {
			x.wantWaiting(x.assign(x.wholeCore))
			restarted := x.bringDown(x.fragmenter)
			x.wantWaiting(x.assign(x.wholeCore))
			x.release(x.fragmenter)
			x.wantPlaced(x.assign(x.wholeCore), x.wholeCore)
			x.setConfig(restarted)
			x.wantPlaced(x.assign(restarted), restarted)
		},
		"member stopping first": func(x *repackFixture) {
			restarted := x.bringDown(x.fragmenter)
			x.wantWaiting(x.assign(x.wholeCore))
			x.release(x.fragmenter)
			x.wantPlaced(x.assign(x.wholeCore), x.wholeCore)
			x.setConfig(restarted)
			x.wantPlaced(x.assign(restarted), restarted)
		},
		"member back first": func(x *repackFixture) {
			restarted := x.bringDown(x.fragmenter)
			x.release(x.fragmenter)
			x.setConfig(restarted)
			x.wantPlaced(x.assign(restarted), restarted)
			x.wantPlaced(x.assign(x.wholeCore), x.wholeCore)
		},
	}
	for name, run := range steps {
		t.Run(name, func(t *testing.T) {
			x := newRepackFixture(t)
			run(x)
			plan := planFor(x.ctx.cpuPlacement.placer, plannedIntents(x.ctx))
			holders := x.ctx.cpuPlacement.placer.Holders()
			for _, config := range []types.DomainConfig{x.wholeCore, x.fragmenter} {
				id := config.UUIDandVersion.UUID
				for _, cpu := range plan[id].Assignment.CPUs() {
					if holders[cpu] != id {
						t.Errorf("%s is not on its planned CPU %d", config.DisplayName, cpu)
					}
				}
			}
			if x.ctx.cpuPlacement.wantsRepack[x.wholeCore.UUIDandVersion.UUID] {
				t.Error("a workload placed as planned no longer wants a repack")
			}
		})
	}
}

// A workload whose planned CPUs are held by one staying where it is does not
// wait: it is placed elsewhere or refused, now.
func TestAssign_DoesNotWaitForAHolderStayingUp(t *testing.T) {
	x := newRepackFixture(t)
	x.ctx.cpuPlacement.forget(x.ctx, x.wholeCore.UUIDandVersion.UUID)
	err := x.assign(x.wholeCore)
	var refusal *placementError
	if !errors.As(err, &refusal) {
		t.Fatalf("want a refusal, got %v", err)
	}
}

// A workload placed off its plan is kept off the CPUs the plan sets aside for
// workloads not started yet: taking them would hand the next workload the same
// problem, and make the layout depend on start order.
func TestAssign_FallbackLeavesPlannedCPUsToWorkloadsNotStarted(t *testing.T) {
	policy := wholeCoreDemand("", 2).CPUPlacement
	var demands []types.AppCPUDemand
	configs := newConfigSubscription()
	for i := 0; i < 3; i++ {
		demand := wholeCoreDemand(fmt.Sprintf("w%d", i), 2)
		demands = append(demands, demand)
		config := pinnedConfigForTest(demand.DisplayName, policy)
		config.Activate = true
		configs.items[config.Key()] = config
	}
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subCPUDemandSet:             testCPUDemandSub(t, testPubSub(t), demands...),
		subDomainConfig:             configs,
		cpuTopologyPinningSupported: true,
	})
	plan := planFor(ctx.cpuPlacement.placer, plannedIntents(ctx))
	// By planned core: b lowest, then x, then a. x runs on a's planned core
	// and a workload nobody plans for holds the fourth, so a falls back to the
	// free cores, b's and x's, and the lower of them is b's.
	slices.SortFunc(demands, func(p, q types.AppCPUDemand) int {
		return int(plan[p.UUID].Assignment.OrderedHostCPUs[0]) -
			int(plan[q.UUID].Assignment.OrderedHostCPUs[0])
	})
	b, x, a := demands[0], demands[1], demands[2]
	if err := ctx.cpuPlacement.placer.Claim(x.UUID, plan[a.UUID].Assignment); err != nil {
		t.Fatal(err)
	}
	used := slices.Concat(plan[a.UUID].Assignment.CPUs(), plan[b.UUID].Assignment.CPUs(),
		plan[x.UUID].Assignment.CPUs())
	var fourth []uint32
	for cpu := cputopology.LCPU(0); cpu < 8; cpu++ {
		if !slices.Contains(used, cpu) {
			fourth = append(fourth, uint32(cpu))
		}
	}
	holdCPUs(t, ctx.cpuPlacement.placer, uuid.NewV5(uuid.NamespaceOID, "y"), fourth...)
	ctx.cpuPlacement.inputsChanged(ctx)

	config := pinnedConfigForTest(a.DisplayName, policy)
	var status types.DomainStatus
	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("a fits on x's planned core: %v", err)
	}
	for _, cpu := range plan[b.UUID].Assignment.CPUs() {
		if slices.Contains(status.Placement.Assigned.CPUs, uint32(cpu)) {
			t.Errorf("a took CPU %d, which the plan sets aside for b", cpu)
		}
	}
}

// io_placement=housekeeping runs the IO threads on the housekeeping set as it
// stands once the workload holds its own CPUs: EVE's and every other CPU no
// workload holds, never a kernel-isolated one.
func TestAssign_IOHousekeeping(t *testing.T) {
	for name, tc := range map[string]struct {
		policy   types.CPUPolicy
		reserved []uint32
		isolated []uint32
		wantIO   []uint32
	}{
		// EVE runs on CPU 0, so core 0 ({0,4}) is withheld from workloads and
		// the workload gets core 1 ({1,5}).
		"every CPU no workload holds": {types.CPUPolicyDedicated, []uint32{0}, nil,
			[]uint32{0, 2, 3, 4, 6, 7}},
		"never an isolated one": {types.CPUPolicyDedicated, []uint32{0}, []uint32{3, 7},
			[]uint32{0, 2, 4, 6}},
	} {
		t.Run(name, func(t *testing.T) {
			io := pinnedConfigForTest("io", types.CPUPlacementPolicy{
				Policy: tc.policy, Pinned: true, FullPCPUsOnly: true,
				IOPlacement: types.CPUIOPlacementHousekeeping,
			})
			ctx := placementContext(t, &domainContext{
				cpuPlacement:                newCPUPlacement(testPlacerReserving(t, tc.reserved, tc.isolated)),
				subDomainConfig:             newConfigSubscription(io),
				cpuTopologyPinningSupported: true,
			})
			var status types.DomainStatus
			if err := ctx.cpuPlacement.assign(ctx, &io, &status); err != nil {
				t.Fatalf("placement failed: %v", err)
			}
			assigned := status.Placement.Assigned
			if !slices.Equal(assigned.IOCPUs, tc.wantIO) {
				t.Errorf("IO CPUs %v, want the housekeeping set %v", assigned.IOCPUs, tc.wantIO)
			}
			if want := slices.Concat(assigned.CPUs, tc.wantIO); !slices.Equal(status.VmConfig.CPUs, want) {
				t.Errorf("the cpuset must be the vCPUs' CPUs and the IO CPUs %v, got %v",
					want, status.VmConfig.CPUs)
			}
			// The non-vCPU threads run there, and the domain starts there, so
			// nothing QEMU sets up while starting names a vCPU's core.
			if got := assigned.EmulatorCPUs(); !slices.Equal(got, tc.wantIO) {
				t.Errorf("emulator CPUs %v, want the IO CPUs %v", got, tc.wantIO)
			}
			if got := status.StartCPUs(); !slices.Equal(got, tc.wantIO) {
				t.Errorf("start CPUs %v, want the IO CPUs %v", got, tc.wantIO)
			}
			for _, cpu := range tc.wantIO {
				if slices.Contains(assigned.CPUs, cpu) || slices.Contains(assigned.ParkedCPUs, cpu) {
					t.Errorf("IO CPU %d is also one of the workload's own", cpu)
				}
			}
		})
	}
}

// A domainmgr restart reseeds what each running workload holds -- its vCPU
// CPUs and parked siblings, not the shared CPUs its IO threads run on -- and
// which of them want a repack.
func TestReseed(t *testing.T) {
	ps := testPubSub(t)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:    newCPUPlacement(testPlacer(t)),
		pubDomainStatus: testPublication(t, ps, types.DomainStatus{}),
	})
	held := types.DomainStatus{
		UUIDandVersion: pinnedConfigForTest("held", types.CPUPlacementPolicy{}).UUIDandVersion,
		Placement: types.CPUPlacementState{
			Verdict: types.CPUPlacementPlacedSuboptimal,
			Assigned: types.CPUAssignment{
				CPUs:       []uint32{1, 2},
				ParkedCPUs: []uint32{5, 6},
				IOCPUs:     []uint32{0},
			},
		},
	}
	shared := types.DomainStatus{
		UUIDandVersion: sharedConfigForTest("shared").UUIDandVersion,
	}
	shared.VmConfig.CPUs = []uint32{0, 3, 4, 7}
	for _, status := range []types.DomainStatus{held, shared} {
		publishDomainStatus(ctx, &status)
	}

	ctx.cpuPlacement.reseed(ctx)

	holders := ctx.cpuPlacement.placer.Holders()
	got := slices.Sorted(func(yield func(cputopology.LCPU) bool) {
		for cpu := range holders {
			if !yield(cpu) {
				return
			}
		}
	})
	if !slices.Equal(got, []cputopology.LCPU{1, 2, 5, 6}) {
		t.Errorf("reseeded %v, want the vCPU CPUs and parked siblings [1 2 5 6]", got)
	}
	if !ctx.cpuPlacement.wantsRepack[held.UUIDandVersion.UUID] {
		t.Error("a workload placed worse than planned still wants a repack")
	}
}

// Workloads placed concurrently never share a CPU.
func TestAssign_ConcurrentPlacementsAreDisjoint(t *testing.T) {
	var configs []types.DomainConfig
	for i := 0; i < 4; i++ {
		config := pinnedConfigForTest(fmt.Sprintf("w%d", i), wholeCoreDemand("", 2).CPUPlacement)
		config.Activate = true
		configs = append(configs, config)
	}
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subDomainConfig:             newConfigSubscription(configs...),
		cpuTopologyPinningSupported: true,
	})
	statuses := make([]types.DomainStatus, len(configs))
	errs := make([]error, len(configs))
	var wg sync.WaitGroup
	for i := range configs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = ctx.cpuPlacement.assign(ctx, &configs[i], &statuses[i])
		}(i)
	}
	wg.Wait()
	seen := map[uint32]string{}
	for i, status := range statuses {
		if errs[i] != nil {
			t.Fatalf("%s: %v", configs[i].DisplayName, errs[i])
		}
		for _, cpu := range slices.Concat(status.Placement.Assigned.CPUs, status.Placement.Assigned.ParkedCPUs) {
			if other, taken := seen[cpu]; taken {
				t.Errorf("CPU %d given to both %s and %s", cpu, other, configs[i].DisplayName)
			}
			seen[cpu] = configs[i].DisplayName
		}
	}
	if len(seen) != 8 {
		t.Errorf("four whole-core workloads fill the node, got %v", seen)
	}
}

// The view is derived again after every change, so a decision never reads one
// computed before the change it follows. Here the only change is to the
// planned set -- the workload the repack is for is no longer configured, and
// its repack flag is still set -- so only a view derived again sees that
// nothing has to move for it any more.
func TestPlacementView_DerivedAfterEveryChange(t *testing.T) {
	x := newRepackFixture(t)
	fragmenter := x.fragmenter.UUIDandVersion.UUID
	before := x.ctx.cpuPlacement.repackFor(x.ctx, fragmenter)

	demands := newConfigSubscription()
	demands.items["global"] = types.CPUDemandSet{Complete: true,
		Apps: []types.AppCPUDemand{threadGranularDemand("fragmenter", 4)}}
	x.ctx.subCPUDemandSet = demands
	unconfigured := x.wholeCore
	unconfigured.Activate = false
	x.setConfig(unconfigured)

	if !x.ctx.cpuPlacement.wantsRepack[x.wholeCore.UUIDandVersion.UUID] {
		t.Fatal("precondition: only the planned set may change, not the repack flag")
	}
	after := x.ctx.cpuPlacement.repackFor(x.ctx, fragmenter)
	if !slices.Equal(before, []string{"wholecore"}) || after != nil {
		t.Errorf("RepackFor %v before the change, %v after; want [wholecore], then cleared",
			before, after)
	}
}

// twoNodeTopology is four SMT2 cores on two NUMA nodes, each node with an L3
// of its own: core c is CPUs c and c+4, on node c/2.
func twoNodeTopology() *cputopology.Topology {
	var infos []cputopology.CPU
	for thread := uint(0); thread < 2; thread++ {
		for core := uint(0); core < 4; core++ {
			infos = append(infos, cputopology.CPU{
				ID: cputopology.LCPU(thread*4 + core), Core: core, NUMA: core / 2,
				L3: cputopology.CacheID{ID: uint32(core / 2), Known: true},
			})
		}
	}
	return cputopology.Build(infos)
}

// A workload whose planned CPUs are held by workloads staying where they are
// runs elsewhere. Where that is worse than its plan -- split across NUMA nodes
// the plan keeps it within -- it is placed suboptimal and wants a repack, and
// the workload standing on its planned CPUs is flagged to move for it. Where
// it is as good, it is simply placed.
func TestAssign_PlacedWorseThanPlannedWantsARepack(t *testing.T) {
	big := wholeCoreDemand("big", 4) // planned onto node 0: cores 0 and 1
	small := wholeCoreDemand("small", 2)
	other := wholeCoreDemand("other", 2)
	for name, tc := range map[string]struct {
		demands []types.AppCPUDemand
		// running maps a workload to the core it runs on.
		running     map[types.AppCPUDemand]uint32
		wantVerdict types.CPUPlacementVerdict
	}{
		// small and other hold a core on each node, so big is split.
		"split across nodes": {[]types.AppCPUDemand{big, small, other},
			map[types.AppCPUDemand]uint32{small: 1, other: 3},
			types.CPUPlacementPlacedSuboptimal},
		// Node 1 is free: big lands there, as good as its plan.
		"on the other node": {[]types.AppCPUDemand{big, small},
			map[types.AppCPUDemand]uint32{small: 1},
			types.CPUPlacementPlaced},
	} {
		t.Run(name, func(t *testing.T) {
			configs := newConfigSubscription()
			for _, demand := range tc.demands {
				configs.items[runningConfig(demand).Key()] = runningConfig(demand)
			}
			placer, err := cpuallocator.NewPlacer(twoNodeTopology(), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := placementContext(t, &domainContext{
				cpuPlacement:                newCPUPlacement(placer),
				subCPUDemandSet:             testCPUDemandSub(t, testPubSub(t), tc.demands...),
				subDomainConfig:             configs,
				cpuTopologyPinningSupported: true,
			})
			for demand, core := range tc.running {
				holdCPUs(t, placer, demand.UUID, core, core+4)
			}
			ctx.cpuPlacement.inputsChanged(ctx)
			planned := planFor(placer, plannedIntents(ctx))[big.UUID].Assignment.CPUs()
			if !slices.Equal(planned, []cputopology.LCPU{0, 4, 1, 5}) {
				t.Fatalf("precondition: big must be planned onto node 0, got %v", planned)
			}

			config := runningConfig(big)
			status := types.DomainStatus{UUIDandVersion: config.UUIDandVersion,
				DisplayName: config.DisplayName}
			if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
				t.Fatalf("big fits among the free cores: %v", err)
			}
			if status.Placement.Verdict != tc.wantVerdict {
				t.Errorf("verdict %v on %v, want %v", status.Placement.Verdict,
					status.Placement.Assigned.CPUs, tc.wantVerdict)
			}
			wantsRepack := tc.wantVerdict == types.CPUPlacementPlacedSuboptimal
			if got := ctx.cpuPlacement.wantsRepack[big.UUID]; got != wantsRepack {
				t.Errorf("wants a repack: %t, want %t", got, wantsRepack)
			}
			var wantRepackFor []string
			if wantsRepack {
				wantRepackFor = []string{"big"}
			}
			if got := ctx.cpuPlacement.repackFor(ctx, small.UUID); !slices.Equal(got, wantRepackFor) {
				t.Errorf("small stands on big's planned core: RepackFor %v, want %v",
					got, wantRepackFor)
			}
		})
	}
}

// A workload retried for a missing adapter or a disk whose format is wrong must
// not take CPUs and give them back on every retry: each claim and release
// publishes the pool report twice and moves the host cpuset. doActivate checks
// both before it places CPUs.
func TestDoActivate_ChecksAdaptersAndDisksBeforePlacing(t *testing.T) {
	setup := func(t *testing.T) (*domainContext, types.DomainConfig, *types.DomainStatus) {
		config := pinnedConfigForTest("checked", threadGranularDemand("checked", 2).CPUPlacement)
		config.Activate = true
		configs := &mapSubscription{items: map[string]interface{}{config.Key(): config}}
		ctx := newRetryBootContext(t, &types.AssignableAdapters{}, configs)
		ctx.cpuPinningSupported = true
		status := &types.DomainStatus{
			UUIDandVersion: config.UUIDandVersion,
			DisplayName:    config.DisplayName,
			// It was waiting for CPUs before the check failed.
			Placement: types.CPUPlacementState{Wait: types.CPUWait{AppSet: true, Since: time.Now()}},
		}
		return ctx, config, status
	}
	placedNothing := func(t *testing.T, ctx *domainContext, status *types.DomainStatus) {
		t.Helper()
		if ctx.cpuPlacement.placer.Holds(status.UUIDandVersion.UUID) {
			t.Error("the workload holds CPUs")
		}
		if n := len(ctx.pubCPUPoolStatus.GetAll()); n != 0 {
			t.Errorf("the pool report was published (%d items)", n)
		}
		if status.Placement.Wait.Waiting() {
			t.Error("the workload is still reported as waiting for CPUs")
		}
	}

	t.Run("missing adapter", func(t *testing.T) {
		ctx, config, status := setup(t)
		config.IoAdapterList = []types.IoAdapter{{Type: types.IoUSB, Name: "usb0"}}
		doActivate(ctx, config, status)
		if !status.AdaptersFailed || !strings.Contains(status.Error, "unknown adapter") {
			t.Fatalf("want AdaptersFailed with the unknown adapter, got %v %q",
				status.AdaptersFailed, status.Error)
		}
		placedNothing(t, ctx, status)
	})

	t.Run("disk format", func(t *testing.T) {
		ctx, config, status := setup(t)
		status.DiskStatusList = []types.DiskStatus{{
			Format:       zconfig.Format_QCOW2,
			FileLocation: filepath.Join(t.TempDir(), "missing.qcow2"),
		}}
		doActivate(ctx, config, status)
		if !status.ConfigFailed || !status.HasError() {
			t.Fatalf("want ConfigFailed with an error, got %v %q",
				status.ConfigFailed, status.Error)
		}
		placedNothing(t, ctx, status)
	})

	t.Run("check reserves nothing", func(t *testing.T) {
		ctx, config, _ := setup(t)
		ctx.assignableAdapters.IoBundleList = []types.IoBundle{{
			Phylabel: "USB1", Logicallabel: "usb0", Type: types.IoUSB,
			AssignmentGroup: "usb0", PciLong: "0000:00:14.0",
		}}
		config.IoAdapterList = []types.IoAdapter{{Type: types.IoUSB, Name: "usb0"}}
		if d := checkAdapters(ctx, config); d != nil {
			t.Fatalf("a free adapter is refused: %s", d.Error)
		}
		if used := ctx.assignableAdapters.IoBundleList[0].UsedByUUID; used != nilUUID {
			t.Errorf("checkAdapters reserved the adapter for %s", used)
		}
		if n := len(ctx.pubAssignableAdapters.GetAll()); n != 0 {
			t.Errorf("checkAdapters published the adapters (%d items)", n)
		}
	})

	// Without those checks failing, the same workload is placed: the cases
	// above do not pass for want of a placement.
	t.Run("control", func(t *testing.T) {
		ctx, config, status := setup(t)
		if err := ctx.cpuPlacement.assign(ctx, &config, status); err != nil {
			t.Fatal(err)
		}
		if !ctx.cpuPlacement.placer.Holds(config.UUIDandVersion.UUID) ||
			len(ctx.pubCPUPoolStatus.GetAll()) == 0 {
			t.Fatal("the workload was not placed")
		}
	})
}

// assigned_cpus.cpu_ids is in vCPU order for a pinned workload, and ascending
// otherwise: a whole-core container's CPUs come from the allocator sibling by
// sibling (core c is CPUs c and c+4 here), an order that means nothing to it.
func TestAssignCPUs_CPUsOfAWorkloadNotPinnedAscend(t *testing.T) {
	for name, tc := range map[string]struct {
		container bool
		want      []uint32
	}{
		"pinned VM, vCPU order":      {want: []uint32{0, 4, 1, 5}},
		"container, ascending order": {container: true, want: []uint32{0, 1, 4, 5}},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := placementContext(t, &domainContext{
				cpuPlacement: newCPUPlacement(testPlacer(t)), cpuTopologyPinningSupported: true})
			config := pinnedConfigForTest("app", types.CPUPlacementPolicy{
				Policy: types.CPUPolicyDedicated, Pinned: !tc.container, FullPCPUsOnly: true,
			})
			config.VmConfig.VCpus = 4
			if tc.container {
				config.VirtualizationMode = types.NOHYPER
			}
			var status types.DomainStatus
			if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
				t.Fatal(err)
			}
			if got := status.Placement.Assigned.CPUs; !slices.Equal(got, tc.want) {
				t.Errorf("assigned CPUs %v, want %v", got, tc.want)
			}
		})
	}
}
