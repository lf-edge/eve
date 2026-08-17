// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// testCPUDemandSub publishes a demand set as zedmanager would and returns a
// subscription over it, so planning has the whole intended set to work from.
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
	set := types.CPUDemandSet{Apps: apps}
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
		CPUsPinned:  true,
		CPUPlacement: types.CPUPlacementPolicy{
			Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
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
		CPUsPinned:  true,
		CPUPlacement: types.CPUPlacementPolicy{
			Policy: types.CPUPolicyDedicated,
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
		out[id] = assignmentCPUs(result.Assignment)
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
	isolatePinningOverride(t)
	smt := wholeCoreDemand("smt-app", 2)
	core := wholeCoreDemand("core-app", 2)
	core.CPUPlacement.ThreadsPerCore = 1

	// The reference: the whole set known, nothing activated yet.
	ps := testPubSub(t)
	ctx := &domainContext{
		placer:          testPlacer(t),
		subCPUDemandSet: testCPUDemandSub(t, ps, smt, core),
		subDomainConfig: testDomainConfigSub(t, ps),
	}
	want := assignedCPUs(planPinnedPlacement(ctx))
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
			ctx := &domainContext{
				placer:          testPlacer(t),
				subCPUDemandSet: testCPUDemandSub(t, ps, tt.apps...),
				subDomainConfig: testDomainConfigSub(t, ps, tt.configs...),
			}
			if got := assignedCPUs(planPinnedPlacement(ctx)); !reflect.DeepEqual(got, want) {
				t.Errorf("placement = %v, want %v -- the plan must depend on the "+
					"demand set alone", got, want)
			}
		})
	}
}

// An app that has a DomainConfig but is not in the demand set is on its way out
// (deleted, or deactivated by a profile change). Planning CPUs for it would set
// aside cores nothing is going to use.
func TestPlanPinnedPlacement_DemandSetIsAuthoritative(t *testing.T) {
	isolatePinningOverride(t)
	ps := testPubSub(t)
	stays := wholeCoreDemand("stays", 2)
	leaving := pinnedConfigForTest("leaving", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})
	ctx := &domainContext{
		placer:          testPlacer(t),
		subCPUDemandSet: testCPUDemandSub(t, ps, stays),
		subDomainConfig: testDomainConfigSub(t, ps, leaving),
	}

	plan := planPinnedPlacement(ctx)
	if _, ok := plan[leaving.UUIDandVersion.UUID]; ok {
		t.Error("an app absent from the demand set must not be planned for")
	}
	if _, ok := plan[stays.UUID]; !ok {
		t.Errorf("the app in the demand set must be planned, got %v", plan)
	}
}

// The demand set carries the controller's intent only: zedmanager cannot see
// the operator-editable /persist override. domainmgr must therefore still apply
// it, or the override -- the only way to ask for whole-core placement on a
// device whose controller knows nothing about the policy -- would plan nothing
// and the workload would land wherever it fitted on the day.
func TestPlanPinnedPlacement_PersistOverrideStillPins(t *testing.T) {
	isolatePinningOverride(t)
	ps := testPubSub(t)
	// No controller intent at all: not pinned, no policy.
	app := types.AppCPUDemand{
		UUID:        uuid.NewV5(uuid.NamespaceOID, "override-planned"),
		DisplayName: "override-planned",
		VCpus:       2,
	}
	ctx := &domainContext{
		placer:          testPlacer(t),
		subCPUDemandSet: testCPUDemandSub(t, ps, app),
		subDomainConfig: testDomainConfigSub(t, ps),
	}

	if plan := planPinnedPlacement(ctx); len(plan) != 0 {
		t.Fatalf("without an override there is nothing to plan, got %v", plan)
	}

	writePinningEntryForTest(t, app.UUID, &PinningEntry{
		CPUPolicy: "static", PolicyOptions: fullPCPUs(), ThreadsPerCore: 1,
	})
	plan := planPinnedPlacement(ctx)
	result, ok := plan[app.UUID]
	if !ok || result.Status != cpuallocator.Success {
		t.Fatalf("the /persist override must reach the plan, got %v", plan)
	}
	// one-per-core: one host CPU per vCPU, with the SMT sibling parked.
	if len(result.Assignment.OrderedHostCPUs) != 2 || len(result.Assignment.ParkedCPUs) != 2 {
		t.Errorf("override asked for one-per-core, got cpus=%v parked=%v",
			result.Assignment.OrderedHostCPUs, result.Assignment.ParkedCPUs)
	}
}

// "No app asked for CPUs" and "zedmanager has not spoken yet" mean opposite
// things. An empty set is an answer and must be honoured; a missing one must
// fall back rather than leave a workload unplanned.
func TestPlanPinnedPlacement_EmptySetIsNotAMissingSet(t *testing.T) {
	isolatePinningOverride(t)
	config := pinnedConfigForTest("pinned", types.CPUPlacementPolicy{
		Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
	})

	ps := testPubSub(t)
	empty := &domainContext{
		placer:          testPlacer(t),
		subCPUDemandSet: testCPUDemandSub(t, ps),
		subDomainConfig: testDomainConfigSub(t, ps, config),
	}
	if plan := planPinnedPlacement(empty); len(plan) != 0 {
		t.Errorf("an explicitly empty demand set means no app is intended to "+
			"run; nothing may be planned, got %v", plan)
	}

	ps = testPubSub(t)
	missing := &domainContext{
		placer:          testPlacer(t),
		subDomainConfig: testDomainConfigSub(t, ps, config),
	}
	plan := planPinnedPlacement(missing)
	if _, ok := plan[config.UUIDandVersion.UUID]; !ok {
		t.Errorf("without a demand set the DomainConfigs must still be planned "+
			"-- a missing message may not stop a workload from starting, got %v",
			plan)
	}
}
