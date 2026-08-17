// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newDemandTestContext builds a zedmanagerContext whose subAppInstanceConfig
// holds the given app configs and whose CPUDemandSet publication can be read
// back, which is all publishCPUDemandSet touches.
func newDemandTestContext(t *testing.T, configs ...types.AppInstanceConfig) *zedmanagerContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	configPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedagent",
		TopicType: types.AppInstanceConfig{},
	})
	assert.NoError(t, err)
	for _, config := range configs {
		assert.NoError(t, configPub.Publish(config.Key(), config))
	}
	// Persistent makes Activate populate the subscription synchronously, so
	// GetAll reflects the published configs without pumping the change channel.
	configSub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceConfig{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, configSub.Activate())

	localSub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   agentName,
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceConfig{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, localSub.Activate())

	demandPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.CPUDemandSet{},
	})
	assert.NoError(t, err)

	return &zedmanagerContext{
		subAppInstanceConfig:      configSub,
		subLocalAppInstanceConfig: localSub,
		pubCPUDemandSet:           demandPub,
	}
}

func publishedDemandSet(t *testing.T, ctx *zedmanagerContext) types.CPUDemandSet {
	t.Helper()
	item, err := ctx.pubCPUDemandSet.Get("global")
	assert.NoError(t, err)
	set, ok := item.(types.CPUDemandSet)
	assert.True(t, ok)
	return set
}

func demandNames(set types.CPUDemandSet) []string {
	var names []string
	for _, app := range set.Apps {
		names = append(names, app.DisplayName)
	}
	return names
}

func appConfigForTest(name string, activate bool, vm types.VmConfig) types.AppInstanceConfig {
	return types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{
			UUID: uuid.NewV5(uuid.NamespaceOID, name), Version: "1",
		},
		DisplayName:    name,
		Activate:       activate,
		FixedResources: vm,
	}
}

// The set is the whole basis for CPU planning, so it must list exactly the apps
// intended to run. An app that is configured but not activated must not appear:
// holding a CPU reservation for it would keep cores away from the workloads
// that do run.
func TestPublishCPUDemandSet_OnlyAppsIntendedToRun(t *testing.T) {
	pinned := types.VmConfig{
		VCpus:      2,
		CPUsPinned: true,
		CPUPlacement: types.CPUPlacementPolicy{
			Policy: types.CPUPolicyDedicated, FullPCPUsOnly: true,
		},
	}
	ctx := newDemandTestContext(t,
		appConfigForTest("running", true, pinned),
		appConfigForTest("halted", false, pinned),
		appConfigForTest("shared", true, types.VmConfig{VCpus: 4}),
	)

	publishCPUDemandSet(ctx)

	set := publishedDemandSet(t, ctx)
	assert.ElementsMatch(t, []string{"running", "shared"}, demandNames(set))

	// The CPU intent must survive the trip: it is the whole point of the topic.
	for _, app := range set.Apps {
		if app.DisplayName != "running" {
			continue
		}
		assert.Equal(t, 2, app.VCpus)
		assert.True(t, app.CPUsPinned)
		assert.Equal(t, types.CPUPolicyDedicated, app.CPUPlacement.Policy)
		assert.True(t, app.CPUPlacement.FullPCPUsOnly)
	}
}

// An app whose profile does not match the node's current profile is not
// intended to run, even though its config says Activate.
func TestPublishCPUDemandSet_ProfileDecidesMembership(t *testing.T) {
	config := appConfigForTest("profiled", true, types.VmConfig{VCpus: 2})
	config.ProfileList = []string{"daytime"}
	ctx := newDemandTestContext(t, config)

	ctx.currentProfile = "nighttime"
	publishCPUDemandSet(ctx)
	assert.Empty(t, publishedDemandSet(t, ctx).Apps,
		"an app the current profile excludes must not hold a CPU reservation")

	ctx.currentProfile = "daytime"
	publishCPUDemandSet(ctx)
	assert.Equal(t, []string{"profiled"}, demandNames(publishedDemandSet(t, ctx)))
}

// Publishing an empty set is what lets domainmgr tell "no app asked for CPUs"
// from "zedmanager has not spoken yet", so it must happen even when there is
// nothing to say.
func TestPublishCPUDemandSet_EmptySetIsPublished(t *testing.T) {
	ctx := newDemandTestContext(t)

	publishCPUDemandSet(ctx)

	set := publishedDemandSet(t, ctx)
	assert.Empty(t, set.Apps)
}

// TestPublishCPUDemandSet_SortedByUUID guards the sort. subAppInstanceConfig.GetAll
// iterates a map, so without it the same set of apps is published in a different
// order every time: domainmgr sees a changed object, re-plans the placement and
// republishes the pool report on every publication, for no reason at all.
func TestPublishCPUDemandSet_SortedByUUID(t *testing.T) {
	// Names, not UUIDs, are what the caller controls; assert below that their
	// UUID order really differs from the order they are added in, otherwise this
	// test would pass without any sort at all.
	insertion := []types.AppInstanceConfig{
		appConfigForTest("alpha", true, types.VmConfig{VCpus: 2}),
		appConfigForTest("bravo", true, types.VmConfig{VCpus: 2}),
		appConfigForTest("charlie", true, types.VmConfig{VCpus: 2}),
	}
	var insertionUUIDs []string
	for _, config := range insertion {
		insertionUUIDs = append(insertionUUIDs, config.UUIDandVersion.UUID.String())
	}
	wantUUIDs := append([]string(nil), insertionUUIDs...)
	sort.Strings(wantUUIDs)
	assert.NotEqual(t, insertionUUIDs, wantUUIDs,
		"pick app names whose UUID order differs from the order they are added in")

	ctx := newDemandTestContext(t, insertion...)

	publishCPUDemandSet(ctx)
	first := publishedDemandSet(t, ctx)

	var gotUUIDs []string
	for _, app := range first.Apps {
		gotUUIDs = append(gotUUIDs, app.UUID.String())
	}
	assert.Equal(t, wantUUIDs, gotUUIDs)

	// The same set must be byte-identical on the next publication, so an
	// unchanged demand set never looks like a change to domainmgr.
	publishCPUDemandSet(ctx)
	second := publishedDemandSet(t, ctx)
	firstJSON, err := json.Marshal(first)
	assert.NoError(t, err)
	secondJSON, err := json.Marshal(second)
	assert.NoError(t, err)
	assert.Equal(t, string(firstJSON), string(secondJSON))
}
