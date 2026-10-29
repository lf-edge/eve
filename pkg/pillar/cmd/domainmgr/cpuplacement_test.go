// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
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
	if !errors.As(err, &refusal) || refusal.Status != types.CPUPlacementStatusNeedsRepack {
		t.Fatalf("precondition: want %s, got %v", types.CPUPlacementStatusNeedsRepack, err)
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
	if err := ctx.cpuPlacement.placer.Reserve(uuid.NewV5(uuid.NamespaceOID, "y"), fourth); err != nil {
		t.Fatal(err)
	}
	ctx.cpuPlacement.inputsChanged(ctx)

	config := pinnedConfigForTest(a.DisplayName, policy)
	var status types.DomainStatus
	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("a fits on x's planned core: %v", err)
	}
	for _, cpu := range plan[b.UUID].Assignment.CPUs() {
		if slices.Contains(status.OrderedCPUs, uint32(cpu)) {
			t.Errorf("a took CPU %d, which the plan sets aside for b", cpu)
		}
	}
}

// io_placement=housekeeping needs CPUs no workload is ever given. A node with
// none refuses the request rather than leave the IO threads on the workload's
// cores while reporting it placed.
func TestAssign_IOHousekeeping(t *testing.T) {
	io := pinnedConfigForTest("io", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
		IOPlacement: types.CPUIOPlacementHousekeeping,
	})
	for others, wantIO := range map[int]bool{2: true, 3: false} {
		t.Run(fmt.Sprintf("%d other workloads", others), func(t *testing.T) {
			demands := []types.AppCPUDemand{{UUID: io.UUIDandVersion.UUID,
				DisplayName: "io", VCpus: 2, CPUPlacement: io.VmConfig.CPUPlacement}}
			for i := 0; i < others; i++ {
				demands = append(demands, wholeCoreDemand(fmt.Sprintf("other%d", i), 2))
			}
			ctx := placementContext(t, &domainContext{
				cpuPlacement:                newCPUPlacement(testPlacer(t)),
				subCPUDemandSet:             testCPUDemandSub(t, testPubSub(t), demands...),
				subDomainConfig:             newConfigSubscription(io),
				cpuTopologyPinningSupported: true,
			})
			var status types.DomainStatus
			err := ctx.cpuPlacement.assign(ctx, &io, &status)
			if !wantIO {
				var refusal *placementError
				if !errors.As(err, &refusal) || refusal.Status != types.CPUPlacementStatusInsufficient {
					t.Fatalf("want %s, got %v", types.CPUPlacementStatusInsufficient, err)
				}
				if ctx.cpuPlacement.placer.Holds(io.UUIDandVersion.UUID) {
					t.Error("a refused workload must hold no CPUs")
				}
				return
			}
			if err != nil {
				t.Fatalf("placement failed: %v", err)
			}
			if len(status.EmulatorCPUs) != 2 || len(status.VmConfig.CPUs) != 4 {
				t.Errorf("want the unplanned core for the IO threads, in the cpuset: "+
					"IO %v, cpuset %v", status.EmulatorCPUs, status.VmConfig.CPUs)
			}
			if got := status.CPUAssignment().IOCPUs; !slices.Equal(got, status.EmulatorCPUs) {
				t.Errorf("the reported IO CPUs %v must be the emulator CPUs %v",
					got, status.EmulatorCPUs)
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
		UUIDandVersion:     pinnedConfigForTest("held", types.CPUPlacementPolicy{}).UUIDandVersion,
		OrderedCPUs:        []uint32{1, 2},
		ParkedCPUs:         []uint32{5, 6},
		EmulatorCPUs:       []uint32{0},
		CPUPlacementStatus: types.CPUPlacementStatusRepackAdvised,
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
		for _, cpu := range slices.Concat(status.OrderedCPUs, status.ParkedCPUs) {
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
// computed before the change it follows.
func TestPlacementView_DerivedAfterEveryChange(t *testing.T) {
	x := newRepackFixture(t)
	before := x.ctx.cpuPlacement.repackFor(x.ctx, x.fragmenter.UUIDandVersion.UUID)
	stopped := x.wholeCore
	stopped.Activate = false
	x.setConfig(stopped)
	x.ctx.cpuPlacement.forget(x.ctx, stopped.UUIDandVersion.UUID)
	after := x.ctx.cpuPlacement.repackFor(x.ctx, x.fragmenter.UUIDandVersion.UUID)
	if before == nil || after != nil {
		t.Errorf("RepackFor %v before the stop, %v after; want set, then cleared", before, after)
	}
}
