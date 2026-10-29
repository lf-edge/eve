// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// testCPUDemandSub publishes a complete demand set as zedmanager would once it
// has the whole configuration, and returns a subscription over it, so planning
// has the whole intended set to work from.
func testCPUDemandSub(t *testing.T, ps *pubsub.PubSub,
	apps ...types.AppCPUDemand) pubsub.Subscription {
	t.Helper()
	// Persistent on both ends so the subscription populates from what is
	// already published, the way a real subscriber picks up existing state.
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedmanager",
		TopicType:  types.CPUDemandSet{},
		Persistent: true,
	})
	if err != nil {
		t.Fatalf("NewPublication(CPUDemandSet): %v", err)
	}
	set := types.CPUDemandSet{Apps: apps, Complete: true}
	if err := pub.Publish(set.Key(), set); err != nil {
		t.Fatalf("Publish(CPUDemandSet): %v", err)
	}
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.CPUDemandSet{},
		Activate:    true,
		Persistent:  true,
	})
	if err != nil {
		t.Fatalf("NewSubscription(CPUDemandSet): %v", err)
	}
	return sub
}

// wholeCoreDemand is an app the controller asked to place on whole physical
// cores.
func wholeCoreDemand(name string, vcpus int) types.AppCPUDemand {
	return types.AppCPUDemand{
		UUID:        uuid.NewV5(uuid.NamespaceOID, name),
		DisplayName: name,
		VCpus:       vcpus,
		CPUPlacement: types.CPUPlacementPolicy{
			Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
		},
	}
}

// threadGranularDemand is an app the controller asked to pin at thread
// granularity: dedicated CPUs, but without full_pcpus_only. It takes individual
// threads, so the physical cores it lands on are left half-owned.
func threadGranularDemand(name string, vcpus int) types.AppCPUDemand {
	return types.AppCPUDemand{
		UUID:        uuid.NewV5(uuid.NamespaceOID, name),
		DisplayName: name,
		VCpus:       vcpus,
		CPUPlacement: types.CPUPlacementPolicy{
			Policy: types.CPUPolicyDedicated,
			Pinned: true,
		},
	}
}

// assignedCPUs flattens a plan into UUID -> occupied CPUs, which is what a
// caller of the plan actually depends on.
func assignedCPUs(plan map[uuid.UUID]cpuallocator.Result) map[uuid.UUID][]uint32 {
	out := map[uuid.UUID][]uint32{}
	for id, result := range plan {
		if result.Status != cpuallocator.Success || result.Assignment == nil {
			continue
		}
		out[id] = lcpusToUint32(result.Assignment.CPUs())
	}
	return out
}

// The bug this replaces: planning ran over the DomainConfigs that had arrived,
// and a DomainConfig only exists once an app's volumes are resolved. Two apps
// whose images download at different speeds therefore got a different layout on
// every boot -- whichever activated first was planned as if it were alone.
//
// Planning must be a function of the demand set alone: the same set, in any
// order, with any subset having reached a DomainConfig, must place identically.
func TestPlanPinnedPlacement_IndependentOfArrivalOrder(t *testing.T) {
	smt := wholeCoreDemand("smt-app", 2)
	core := wholeCoreDemand("core-app", 2)
	core.CPUPlacement.ThreadsPerCore = 1

	// The reference: the whole set known, nothing activated yet.
	ps := testPubSub(t)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:    newCPUPlacement(testPlacer(t)),
		subCPUDemandSet: testCPUDemandSub(t, ps, smt, core),
		subDomainConfig: testDomainConfigSub(t, ps),
	})
	want := assignedCPUs(planFor(ctx.cpuPlacement.placer, plannedIntents(ctx)))
	if len(want) != 2 {
		t.Fatalf("both apps must be planned, got %v", want)
	}

	// The same set, entries in the other order, and with only one of the two
	// apps far enough along to have a DomainConfig -- the situation that used
	// to decide the layout.
	dc := pinnedConfigForTest("smt-app", smt.CPUPlacement)
	for _, tt := range []struct {
		name    string
		apps    []types.AppCPUDemand
		configs []types.DomainConfig
	}{
		{"reversed demand order", []types.AppCPUDemand{core, smt}, nil},
		{"only one app has a DomainConfig", []types.AppCPUDemand{smt, core},
			[]types.DomainConfig{dc}},
		{"reversed, only one DomainConfig", []types.AppCPUDemand{core, smt},
			[]types.DomainConfig{dc}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ps := testPubSub(t)
			ctx := placementContext(t, &domainContext{
				cpuPlacement:    newCPUPlacement(testPlacer(t)),
				subCPUDemandSet: testCPUDemandSub(t, ps, tt.apps...),
				subDomainConfig: testDomainConfigSub(t, ps, tt.configs...),
			})
			if got := assignedCPUs(planFor(ctx.cpuPlacement.placer, plannedIntents(ctx))); !reflect.DeepEqual(got, want) {
				t.Errorf("placement = %v, want %v -- the plan must depend on the "+
					"demand set alone", got, want)
			}
		})
	}
}

// An app is planned when the demand set names it or its DomainConfig asks for
// activation: either source may be ahead of the other, and neither may leave a
// workload that is about to start unplanned. A stopped app that the demand set
// no longer names holds no plan, so no cores are set aside for it.
func TestPlannedIntents_DemandSetOrActivatedConfig(t *testing.T) {
	stays := wholeCoreDemand("stays", 2)
	policy := types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, Pinned: true, FullPCPUsOnly: true,
	}
	stopped := pinnedConfigForTest("stopped", policy)
	starting := pinnedConfigForTest("starting", policy)
	starting.Activate = true

	for name, demand := range map[string][]types.AppCPUDemand{
		"demand set lagging": {stays},
		"no demand set yet":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			ps := testPubSub(t)
			ctx := placementContext(t, &domainContext{
				cpuPlacement:    newCPUPlacement(testPlacer(t)),
				subDomainConfig: testDomainConfigSub(t, ps, stopped, starting),
			})
			if demand != nil {
				ctx.subCPUDemandSet = testCPUDemandSub(t, ps, demand...)
			}
			intents := plannedIntents(ctx)
			if _, ok := intents[stopped.UUIDandVersion.UUID]; ok {
				t.Error("a stopped app the demand set does not name must not be planned")
			}
			if _, ok := intents[starting.UUIDandVersion.UUID]; !ok {
				t.Error("an app whose DomainConfig asks for activation must be planned")
			}
			if _, ok := intents[stays.UUID]; !ok && demand != nil {
				t.Error("an app the demand set names must be planned")
			}
		})
	}
}

// The DomainConfig is what the workload is created from, so its intent wins
// over a demand set that has not caught up with a change.
func TestPlannedIntents_ConfigIntentWins(t *testing.T) {
	demand := wholeCoreDemand("app", 2)
	config := pinnedConfigForTest("app", demand.CPUPlacement)
	config.VmConfig.VCpus = 4
	ps := testPubSub(t)
	ctx := placementContext(t, &domainContext{
		cpuPlacement:    newCPUPlacement(testPlacer(t)),
		subCPUDemandSet: testCPUDemandSub(t, ps, demand),
		subDomainConfig: testDomainConfigSub(t, ps, config),
	})
	if got := plannedIntents(ctx)[demand.UUID].vcpus; got != 4 {
		t.Errorf("planned for %d vCPUs, want the DomainConfig's 4", got)
	}
}

// After a boot zedmanager publishes its demand set as it works through the app
// configs, and domainmgr can be handed an app's DomainConfig while its copy of
// the set is still partial: the two topics arrive in no fixed order. Placed
// against part of the set, the app takes CPUs the full plan gives to another,
// so it waits until the set is complete, and then gets its planned CPUs.
func TestAssign_WaitsForTheCompleteDemandSet(t *testing.T) {
	small := wholeCoreDemand("n6", 2)
	big := wholeCoreDemand("n8", 4)
	demands := newConfigSubscription()
	demands.items["global"] = types.CPUDemandSet{Apps: []types.AppCPUDemand{small}}
	ctx := placementContext(t, &domainContext{
		cpuPlacement:                newCPUPlacement(testPlacer(t)),
		subCPUDemandSet:             demands,
		cpuTopologyPinningSupported: true,
	})
	alone := planFor(ctx.cpuPlacement.placer, plannedIntents(ctx))[small.UUID]

	config := pinnedConfigForTest("n6", small.CPUPlacement)
	var status types.DomainStatus
	err := ctx.cpuPlacement.assign(ctx, &config, &status)
	var waiting *placementWaiting
	if !errors.As(err, &waiting) || !waiting.appSet {
		t.Fatalf("a partial demand set must make n6 wait for the whole set, got %v", err)
	}
	if len(status.OrderedCPUs) > 0 || ctx.cpuPlacement.placer.Holds(small.UUID) {
		t.Fatalf("n6 must hold no CPUs while it waits, holds %v", status.OrderedCPUs)
	}

	demands.items["global"] = types.CPUDemandSet{
		Apps: []types.AppCPUDemand{small, big}, Complete: true}
	ctx.cpuPlacement.inputsChanged(ctx)
	full := planFor(ctx.cpuPlacement.placer, plannedIntents(ctx))[small.UUID]
	if slices.Equal(alone.Assignment.OrderedHostCPUs, full.Assignment.OrderedHostCPUs) {
		t.Fatalf("the test needs n6 planned differently alone (%v) and with n8 (%v)",
			alone.Assignment.OrderedHostCPUs, full.Assignment.OrderedHostCPUs)
	}
	if err := ctx.cpuPlacement.assign(ctx, &config, &status); err != nil {
		t.Fatalf("with the complete set n6 must be placed: %v", err)
	}
	if !slices.Equal(status.OrderedCPUs, lcpusToUint32(full.Assignment.OrderedHostCPUs)) {
		t.Errorf("n6 placed on %v, the plan for the whole set gives it %v",
			status.OrderedCPUs, full.Assignment.OrderedHostCPUs)
	}
}
