// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/sema"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// fakeTask keeps its domains in memory: they are created, started, stopped and
// deleted as asked, so a workload can go through its real activation and
// teardown. setupErr and startErr make those steps fail. Everything else is
// the null hypervisor's.
type fakeTask struct {
	types.Task
	setupErr, startErr error
	ids                map[string]int
	running            map[string]bool
	lastID             int
}

func (f *fakeTask) Setup(types.DomainStatus, types.DomainConfig,
	*types.AssignableAdapters, *types.ConfigItemValueMap, *os.File) error {
	return f.setupErr
}

func (f *fakeTask) Create(name string, _ string, _ *types.DomainConfig) (int, error) {
	f.lastID++
	f.ids[name] = f.lastID
	return f.lastID, nil
}

func (f *fakeTask) Start(name string) error {
	if f.startErr != nil {
		return f.startErr
	}
	if _, ok := f.ids[name]; !ok {
		return fmt.Errorf("no domain %s", name)
	}
	f.running[name] = true
	return nil
}

func (f *fakeTask) Stop(name string, _ bool) error {
	delete(f.running, name)
	return nil
}

func (f *fakeTask) Delete(name string) error {
	delete(f.ids, name)
	delete(f.running, name)
	return nil
}

func (f *fakeTask) Cleanup(string) error { return nil }

func (f *fakeTask) Info(name string) (int, types.SwState, error) {
	id, ok := f.ids[name]
	switch {
	case !ok:
		return 0, types.UNKNOWN, fmt.Errorf("no domain %s", name)
	case f.running[name]:
		return id, types.RUNNING, nil
	}
	return id, types.HALTED, nil
}

// fakeHyper hands out the fake task and reports caps as its capabilities.
type fakeHyper struct {
	hypervisor.Hypervisor
	task *fakeTask
	caps types.Capabilities
}

func (h *fakeHyper) Task(*types.DomainStatus) types.Task { return h.task }
func (h *fakeHyper) PCIReserve(string) error             { return nil }
func (h *fakeHyper) PCIRelease(string) error             { return nil }
func (h *fakeHyper) GetCapabilities() (*types.Capabilities, error) {
	caps := h.caps
	return &caps, nil
}

func newFakeHyper(t *testing.T, caps types.Capabilities) *fakeHyper {
	t.Helper()
	null, err := hypervisor.GetHypervisor("null")
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHyper{Hypervisor: null, caps: caps, task: &fakeTask{
		Task: null.Task(&types.DomainStatus{}),
		ids:  map[string]int{}, running: map[string]bool{},
	}}
}

// lifecycle is a node on which workloads go through domainmgr's real
// activation, deactivation and deletion, against a fake hypervisor: the
// handlers runHandler calls, with the CPU placement of testPlacer.
type lifecycle struct {
	t       *testing.T
	ctx     *domainContext
	task    *fakeTask
	configs *configSubscription
	// demands holds the demand set, complete unless a test makes it partial.
	demands *configSubscription
}

func newLifecycle(t *testing.T, demands ...types.AppCPUDemand) *lifecycle {
	t.Helper()
	h := newFakeHyper(t, types.Capabilities{})
	savedHyper := hyper
	hyper = h
	t.Cleanup(func() { hyper = savedHyper })
	savedDomDir := domDirname
	domDirname = t.TempDir()
	t.Cleanup(func() { domDirname = savedDomDir })
	// Deleting a workload hands USB back to the host: mark the drivers loaded
	// so that runs no modprobe.
	savedDrivers := slices.Clone(usbDrivers)
	for i := range usbDrivers {
		usbDrivers[i].loaded = types.TS_ENABLED
	}
	t.Cleanup(func() { copy(usbDrivers, savedDrivers) })

	ps := testPubSub(t)
	pubCapabilities := testPublication(t, ps, types.Capabilities{})
	if err := pubCapabilities.Publish("global", types.Capabilities{
		CPUPinning: true, CPUTopologyPinning: true}); err != nil {
		t.Fatal(err)
	}
	createSema := sema.New(log, 1)
	createSema.P(1)
	l := &lifecycle{t: t, task: h.task, configs: newConfigSubscription(),
		demands: newConfigSubscription()}
	l.demands.items["global"] = types.CPUDemandSet{Apps: demands, Complete: true}
	l.ctx = placementContext(t, &domainContext{
		ps:                          ps,
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		cpuPinningSupported:         true,
		cpuTopologyPinningSupported: true,
		subCPUDemandSet:             l.demands,
		subDomainConfig:             l.configs,
		pubDomainStatus:             testPublication(t, ps, types.DomainStatus{}),
		pubCPUPoolStatus:            testPublication(t, ps, types.CPUPoolStatus{}),
		pubDomainMetric:             testPublication(t, ps, types.DomainMetric{}),
		assignableAdapters:          &types.AssignableAdapters{Initialized: true},
		pubAssignableAdapters:       testPublication(t, ps, types.AssignableAdapters{}),
		pubCapabilities:             pubCapabilities,
		subGlobalConfig: &mapSubscription{items: map[string]interface{}{
			"global": *types.DefaultConfigItemValueMap(),
		}},
		subNodeAgentStatus:  &mapSubscription{},
		createSema:          createSema,
		domainBootRetryTime: 600,
		usbAccess:           true,
		vgaAccess:           true,
	})
	return l
}

// lifecycleConfig is the DomainConfig of a VM that asks for demand's CPUs.
func lifecycleConfig(demand types.AppCPUDemand, appNum int) types.DomainConfig {
	config := runningConfig(demand)
	config.UUIDandVersion.Version = "1"
	config.AppNum = appNum
	config.VirtualizationMode = types.HVM
	config.DisableVirtualTPM = true
	return config
}

// apply is a DomainConfig change as runHandler handles it.
func (l *lifecycle) apply(config types.DomainConfig) {
	l.t.Helper()
	key := config.Key()
	l.configs.items[key] = config
	l.ctx.cpuPlacement.inputsChanged(l.ctx)
	if status := lookupDomainStatus(l.ctx, key); status == nil {
		handleCreate(l.ctx, key, &config)
	} else {
		handleModify(l.ctx, key, &config, status)
	}
}

// remove is a DomainConfig deletion as runHandler handles it.
func (l *lifecycle) remove(config types.DomainConfig) {
	l.t.Helper()
	key := config.Key()
	delete(l.configs.items, key)
	l.ctx.cpuPlacement.inputsChanged(l.ctx)
	status := lookupDomainStatus(l.ctx, key)
	if status == nil {
		l.t.Fatalf("no DomainStatus for %s", config.DisplayName)
	}
	handleDelete(l.ctx, key, status)
}

// published is the DomainStatus the rest of the device sees.
func (l *lifecycle) published(config types.DomainConfig) types.DomainStatus {
	l.t.Helper()
	item, err := l.ctx.pubDomainStatus.Get(config.Key())
	if err != nil {
		l.t.Fatalf("no DomainStatus published for %s: %v", config.DisplayName, err)
	}
	return item.(types.DomainStatus)
}

func (l *lifecycle) holds(config types.DomainConfig) bool {
	return l.ctx.cpuPlacement.placer.Holds(config.UUIDandVersion.UUID)
}

// A workload waiting for the complete demand set is activated by
// refreshPlacement once the set is complete. Whatever the activation leads to
// -- running, or failed -- the rest of the device has to see it: what
// refreshPlacement leaves unpublished, zedmanager and the controller never
// learn.
func TestRefreshPlacement_PublishesTheActivationOfAWaitingWorkload(t *testing.T) {
	for name, tc := range map[string]struct {
		setupErr, startErr error
		check              func(t *testing.T, l *lifecycle, published types.DomainStatus)
	}{
		"it starts": {check: func(t *testing.T, l *lifecycle, published types.DomainStatus) {
			if !published.Activated || published.State != types.RUNNING || published.HasError() {
				t.Errorf("want it published running, got activated %t, state %s, error %q",
					published.Activated, published.State, published.Error)
			}
			if published.Placement.Verdict != types.CPUPlacementPlaced ||
				len(published.Placement.Assigned.CPUs) != 2 {
				t.Errorf("want it published placed on 2 CPUs, got %+v", published.Placement)
			}
		}},
		"its domain does not start": {startErr: errors.New("qemu exited"),
			check: func(t *testing.T, l *lifecycle, published types.DomainStatus) {
				if !published.HasError() || !published.BootFailed ||
					published.State != types.BROKEN {
					t.Errorf("want the boot failure published, got state %s, boot "+
						"failed %t, error %q", published.State, published.BootFailed,
						published.Error)
				}
			}},
		"its domain cannot be set up": {setupErr: errors.New("no such disk"),
			check: func(t *testing.T, l *lifecycle, published types.DomainStatus) {
				if !published.HasError() || published.Activated {
					t.Errorf("want the failure published, got activated %t, error %q",
						published.Activated, published.Error)
				}
			}},
	} {
		t.Run(name, func(t *testing.T) {
			demand := wholeCoreDemand("waiter", 2)
			l := newLifecycle(t, demand)
			l.demands.items["global"] = types.CPUDemandSet{Apps: []types.AppCPUDemand{demand}}
			config := lifecycleConfig(demand, 1)
			l.apply(config)
			if wait := l.published(config).Placement.Wait; !wait.AppSet {
				t.Fatalf("precondition: want it waiting for the demand set, got %+v", wait)
			}

			l.task.setupErr, l.task.startErr = tc.setupErr, tc.startErr
			l.demands.items["global"] = types.CPUDemandSet{
				Apps: []types.AppCPUDemand{demand}, Complete: true}
			l.ctx.cpuPlacement.inputsChanged(l.ctx)
			refreshPlacement(l.ctx, config.Key())

			published := l.published(config)
			if published.Placement.Wait.Waiting() {
				t.Errorf("the wait is over, but it is published as %+v", published.Placement.Wait)
			}
			// What the status says it holds is what it holds.
			if got, held := published.Placement.Assigned.Holds(), l.holds(config); got != held {
				t.Errorf("published as holding CPUs: %t, holds CPUs: %t", got, held)
			}
			tc.check(t, l, published)
		})
	}
}

// A workload whose domain failed to boot keeps its CPUs for the boot retry,
// and deleting it gives them back: to the placer, and in the pool report.
func TestHandleDelete_ReleasesTheCPUsOfABootFailedWorkload(t *testing.T) {
	demand := wholeCoreDemand("bootfails", 2)
	l := newLifecycle(t, demand)
	l.task.startErr = errors.New("qemu exited")
	config := lifecycleConfig(demand, 1)
	l.apply(config)
	failed := l.published(config)
	if !failed.BootFailed || !l.holds(config) || !failed.Placement.Assigned.Holds() {
		t.Fatalf("precondition: want a boot failure holding its CPUs, got boot "+
			"failed %t, held %t, %+v", failed.BootFailed, l.holds(config), failed.Placement)
	}
	cpus := failed.Placement.Assigned.CPUs

	l.remove(config)

	if l.holds(config) {
		t.Error("a deleted workload must hold no CPUs")
	}
	pools := publishedPools(t, l.ctx.pubCPUPoolStatus)
	if dedicated := poolOfKind(t, pools, types.CPUPoolKindDedicated); len(dedicated.CPUs) != 0 {
		t.Errorf("no workload holds CPUs, but the dedicated pool is %v", dedicated.CPUs)
	}
	free := poolOfKind(t, pools, types.CPUPoolKindHousekeeping).FreeCPUs
	for _, cpu := range cpus {
		if !slices.Contains(free, cpu) {
			t.Errorf("CPU %d of the deleted workload is not free: %v", cpu, free)
		}
	}
	if _, err := l.ctx.pubDomainStatus.Get(config.Key()); err == nil {
		t.Error("the DomainStatus of a deleted workload must be unpublished")
	}
}

// A node whose CPU topology could not be read places no workload on CPUs of
// its own, so it must not advertise that it can: zedagent reports
// CPUTopologyPinning as OptionalCapabilities.cpu_placement, which the
// controller gates the placement fields on.
func TestGetAndPublishCapabilities_DegradedTopologyCannotPlace(t *testing.T) {
	for name, degraded := range map[string]bool{
		"topology read":     false,
		"topology degraded": true,
	} {
		t.Run(name, func(t *testing.T) {
			topo := testTopology()
			topo.Degraded = degraded
			placer, err := cpuallocator.NewPlacer(topo, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &domainContext{
				cpuPlacement:    newCPUPlacement(placer),
				pubCapabilities: testPublication(t, testPubSub(t), types.Capabilities{}),
			}
			h := newFakeHyper(t, types.Capabilities{CPUPinning: true,
				CPUTopologyPinning: true, IOVirtualization: true})

			if err := getAndPublishCapabilities(ctx, h); err != nil {
				t.Fatal(err)
			}
			caps, err := lookupCapabilities(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if caps.CPUTopologyPinning == degraded {
				t.Errorf("CPUTopologyPinning = %t on a node whose topology is degraded: %t",
					caps.CPUTopologyPinning, degraded)
			}
			if !caps.IOVirtualization {
				t.Error("the hypervisor's other capabilities must pass through")
			}
		})
	}
}

// A controller restart that keeps the task name (the version is unchanged)
// brings the workload back through activation, which records the restart's
// counters. A plain stop after it is then a stop, not another restart, and
// ends the workload's part in a repack: without the counters it would keep its
// repack flag, and the workloads in its way would stay flagged to move.
func TestHandleModify_StopAfterARestartEndsTheRepack(t *testing.T) {
	fragmenterDemand := threadGranularDemand("fragmenter", 4)
	wholeCoreDemand := wholeCoreDemand("wholecore", 2)
	l := newLifecycle(t, fragmenterDemand, wholeCoreDemand)
	fragmenter := lifecycleConfig(fragmenterDemand, 1)
	fragmenter.VmConfig.VCpus = 4
	l.configs.items[fragmenter.Key()] = fragmenter
	startThreadGranularApp(t, l.ctx, fragmenterDemand)
	id := wholeCoreDemand.UUID
	repackFor := func() []string {
		return l.ctx.cpuPlacement.repackFor(l.ctx, fragmenterDemand.UUID)
	}

	config := lifecycleConfig(wholeCoreDemand, 2)
	l.apply(config)
	if v := l.published(config).Placement.Verdict; v != types.CPUPlacementNeedsRepack {
		t.Fatalf("precondition: want it refused as %v, got %v", types.CPUPlacementNeedsRepack, v)
	}

	// The controller restarts the repack set: down with a new restart
	// counter, then up with the same version. The restart is part of the
	// repack, which goes on.
	config.Activate = false
	config.RestartCounter++
	l.apply(config)
	config.Activate = true
	l.apply(config)
	if got := l.published(config).RestartCounter; got != config.RestartCounter {
		t.Errorf("activation recorded restart counter %d, want %d", got, config.RestartCounter)
	}
	if !l.ctx.cpuPlacement.wantsRepack[id] || !slices.Equal(repackFor(), []string{"wholecore"}) {
		t.Fatalf("a restart for the repack must keep it going: flagged %t, "+
			"fragmenter RepackFor %v", l.ctx.cpuPlacement.wantsRepack[id], repackFor())
	}

	// A plain stop.
	config.Activate = false
	l.apply(config)
	if l.ctx.cpuPlacement.wantsRepack[id] {
		t.Error("a stopped workload no longer wants a repack")
	}
	if got := repackFor(); got != nil {
		t.Errorf("nothing is left to repack for, but the fragmenter has RepackFor %v", got)
	}
}

// Stopping a refused workload ends the refusal together with its error: a
// workload published as refused without the error says nothing about why.
// On EVE-k a stop that keeps the VMIRS clears the error without deactivating
// the domain, so nothing releases the verdict there.
func TestHandleModify_StopEndsARefusal(t *testing.T) {
	for name, kube := range map[string]bool{
		"kvm":                        false,
		"kubevirt keeping the VMIRS": true,
	} {
		t.Run(name, func(t *testing.T) {
			fragmenterDemand := threadGranularDemand("fragmenter", 4)
			wholeCoreDemand := wholeCoreDemand("wholecore", 2)
			l := newLifecycle(t, fragmenterDemand, wholeCoreDemand)
			fragmenter := lifecycleConfig(fragmenterDemand, 1)
			fragmenter.VmConfig.VCpus = 4
			l.configs.items[fragmenter.Key()] = fragmenter
			startThreadGranularApp(t, l.ctx, fragmenterDemand)
			config := lifecycleConfig(wholeCoreDemand, 2)
			l.apply(config)
			if p := l.published(config); p.Placement.Verdict != types.CPUPlacementNeedsRepack ||
				!p.HasError() {
				t.Fatalf("precondition: want it refused as %v with an error, got %v %q",
					types.CPUPlacementNeedsRepack, p.Placement.Verdict, p.Error)
			}

			l.ctx.hvTypeKube = kube
			config.UserActivate = kube
			config.Activate = false
			l.apply(config)

			p := l.published(config)
			if p.Placement.Verdict != types.CPUPlacementUnspecified || p.HasError() {
				t.Errorf("a stopped workload is no longer refused: verdict %v, error %q",
					p.Placement.Verdict, p.Error)
			}
		})
	}
}

// A workload gives its CPUs back when it stops and when its domain cannot be
// set up, as it gives back an assigned adapter: to the placer, and in the pool
// report.
func TestCPUsAreReleased(t *testing.T) {
	for name, tc := range map[string]struct {
		setupErr error
		stop     bool
	}{
		"on a stop":          {stop: true},
		"on a Setup failure": {setupErr: errors.New("no such disk")},
	} {
		t.Run(name, func(t *testing.T) {
			demand := wholeCoreDemand("released", 2)
			l := newLifecycle(t, demand)
			l.task.setupErr = tc.setupErr
			config := lifecycleConfig(demand, 1)
			l.apply(config)
			if tc.stop {
				if p := l.published(config); !p.Activated || !l.holds(config) {
					t.Fatalf("precondition: want it running on its CPUs, got activated "+
						"%t, held %t", p.Activated, l.holds(config))
				}
				config.Activate = false
				l.apply(config)
			}

			if l.holds(config) {
				t.Error("the workload still holds CPUs")
			}
			if p := l.published(config); p.Placement.Assigned.Holds() {
				t.Errorf("the workload is published as holding %v", p.Placement.Assigned)
			}
			pools := publishedPools(t, l.ctx.pubCPUPoolStatus)
			if dedicated := poolOfKind(t, pools, types.CPUPoolKindDedicated); len(dedicated.CPUs) != 0 {
				t.Errorf("no workload holds CPUs, but the dedicated pool is %v", dedicated.CPUs)
			}
		})
	}
}

// A refusal clears a stale AdaptersFailed: maybeRetryAdapters would otherwise
// activate the refused workload again on the next adapter change, a retry no
// refusal gets.
func TestDoActivate_RefusalClearsAdaptersFailed(t *testing.T) {
	fragmenterDemand := threadGranularDemand("fragmenter", 4)
	wholeCoreDemand := wholeCoreDemand("wholecore", 2)
	l := newLifecycle(t, fragmenterDemand, wholeCoreDemand)
	fragmenter := lifecycleConfig(fragmenterDemand, 1)
	fragmenter.VmConfig.VCpus = 4
	l.configs.items[fragmenter.Key()] = fragmenter
	startThreadGranularApp(t, l.ctx, fragmenterDemand)
	config := lifecycleConfig(wholeCoreDemand, 2)
	l.configs.items[config.Key()] = config

	status := &types.DomainStatus{UUIDandVersion: config.UUIDandVersion,
		DisplayName: config.DisplayName, AdaptersFailed: true}
	doActivate(l.ctx, config, status)

	if status.Placement.Verdict != types.CPUPlacementNeedsRepack {
		t.Fatalf("precondition: want it refused as %v, got %v",
			types.CPUPlacementNeedsRepack, status.Placement.Verdict)
	}
	if status.AdaptersFailed {
		t.Error("a refused workload must not keep AdaptersFailed")
	}
}
