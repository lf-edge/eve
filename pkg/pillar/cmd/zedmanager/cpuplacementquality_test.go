// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newPlacementQualityTestContext builds a zedmanagerContext wired for the
// activate/inactivate paths: zedmanager's own DomainConfig and AppNetworkConfig
// publications, plus the domainmgr and zedrouter status subscriptions those paths
// read. A nil ds leaves subDomainStatus empty, which is what a torn-down app
// looks like.
func newPlacementQualityTestContext(t *testing.T, ds *types.DomainStatus,
	ns *types.AppNetworkStatus) *zedmanagerContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	newPub := func(agent string, topic interface{}) pubsub.Publication {
		pub, err := ps.NewPublication(pubsub.PublicationOptions{
			AgentName: agent,
			TopicType: topic,
		})
		assert.NoError(t, err)
		return pub
	}
	// Persistent makes Activate load the published status through the driver, so
	// Get() sees it without pumping the change channel.
	newSub := func(agent string, topic interface{}) pubsub.Subscription {
		sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName:   agent,
			MyAgentName: agentName,
			TopicImpl:   topic,
			Persistent:  true,
		})
		assert.NoError(t, err)
		assert.NoError(t, sub.Activate())
		return sub
	}

	domainmgrPub := newPub("domainmgr", types.DomainStatus{})
	if ds != nil {
		assert.NoError(t, domainmgrPub.Publish(ds.Key(), *ds))
	}
	zedrouterPub := newPub("zedrouter", types.AppNetworkStatus{})
	if ns != nil {
		assert.NoError(t, zedrouterPub.Publish(ns.Key(), *ns))
	}

	return &zedmanagerContext{
		pubDomainConfig:     newPub(agentName, types.DomainConfig{}),
		pubAppNetworkConfig: newPub(agentName, types.AppNetworkConfig{}),
		subDomainStatus:     newSub("domainmgr", types.DomainStatus{}),
		subAppNetworkStatus: newSub("zedrouter", types.AppNetworkStatus{}),
	}
}

// placementQualityFixture returns a running app and the domainmgr/zedrouter
// statuses that let doActivate run to the end.
func placementQualityFixture(quality types.CPUPlacementQuality) (types.AppInstanceConfig,
	*types.AppInstanceStatus, *types.DomainStatus, *types.AppNetworkStatus) {

	uuidAndVersion := types.UUIDandVersion{
		UUID:    uuid.NewV5(uuid.NamespaceOID, "pinned-app"),
		Version: "1",
	}
	config := types.AppInstanceConfig{
		UUIDandVersion: uuidAndVersion,
		DisplayName:    "pinned-app",
		Activate:       true,
		FixedResources: types.VmConfig{VCpus: 4, Memory: 1024, CPUsPinned: true},
	}
	// Activated skips the memory admission check, which is the state an app is in
	// when domainmgr re-evaluates its placement.
	status := &types.AppInstanceStatus{
		UUIDandVersion: uuidAndVersion,
		DisplayName:    "pinned-app",
		State:          types.RUNNING,
		Activated:      true,
	}
	ds := &types.DomainStatus{
		UUIDandVersion:   uuidAndVersion,
		DisplayName:      "pinned-app",
		DomainName:       "pinned-app.1.1",
		State:            types.RUNNING,
		Activated:        true,
		PlacementQuality: quality,
	}
	ns := &types.AppNetworkStatus{
		UUIDandVersion: uuidAndVersion,
		DisplayName:    "pinned-app",
		Activated:      true,
	}
	return config, status, ds, ns
}

// TestDoActivate_CopiesPlacementQualityFromDomainStatus is the zedmanager link in
// the chain that carries a sub-optimal placement to the controller: domainmgr
// computes it on DomainStatus, zedmanager copies it onto AppInstanceStatus, and
// zedagent turns it into an advisory. Without this copy the device works out that
// a repack would help and then keeps it to itself.
func TestDoActivate_CopiesPlacementQualityFromDomainStatus(t *testing.T) {
	config, status, ds, ns := placementQualityFixture(types.CPUPlacementQualityNeedsRepack)
	ctx := newPlacementQualityTestContext(t, ds, ns)

	doActivate(ctx, status.Key(), config, status)

	assert.Equal(t, types.CPUPlacementQualityNeedsRepack, status.PlacementQuality)
	// It is status, not a failure: a workload placed sub-optimally keeps running.
	assert.False(t, status.HasError())
	assert.Equal(t, types.RUNNING, status.State)
}

// TestDoActivate_FollowsPlacementQualityBackToOptimal covers the other direction:
// once neighbouring workloads have moved, the same app is optimally placed and
// the advisory has to go away. A copy that only ever set "needs repack" would
// leave the controller nagging about a workload that is now placed as well as it
// can be.
func TestDoActivate_FollowsPlacementQualityBackToOptimal(t *testing.T) {
	config, status, ds, ns := placementQualityFixture(types.CPUPlacementQualityOptimal)
	status.PlacementQuality = types.CPUPlacementQualityNeedsRepack
	ctx := newPlacementQualityTestContext(t, ds, ns)

	doActivate(ctx, status.Key(), config, status)

	assert.Equal(t, types.CPUPlacementQualityOptimal, status.PlacementQuality)
}

// TestDoInactivate_ClearsPlacementQuality checks the teardown side: a torn-down
// workload holds no CPUs, so there is no placement left to judge. A stale
// "needs repack" would keep an advisory on the wire for an app that is not even
// running, and would survive into the next activation as a wrong starting value.
func TestDoInactivate_ClearsPlacementQuality(t *testing.T) {
	_, status, _, _ := placementQualityFixture(types.CPUPlacementQualityNeedsRepack)
	status.PlacementQuality = types.CPUPlacementQualityNeedsRepack
	// Nothing published for the app any more: domainmgr has removed the domain
	// and zedrouter the network.
	ctx := newPlacementQualityTestContext(t, nil, nil)

	changed, done := doInactivate(ctx, status.UUIDandVersion.UUID, status)

	assert.True(t, done)
	assert.True(t, changed)
	assert.Equal(t, types.CPUPlacementQualityUnspecified, status.PlacementQuality)
}
