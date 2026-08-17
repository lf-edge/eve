// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newCPUPlacementTestContext builds a zedmanagerContext wired for the
// activate/inactivate paths: zedmanager's own DomainConfig and AppNetworkConfig
// publications, plus the domainmgr and zedrouter status subscriptions those paths
// read. A nil ds leaves subDomainStatus empty, which is what a torn-down app
// looks like.
func newCPUPlacementTestContext(t *testing.T, ds *types.DomainStatus,
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

// cpuPlacementFixture returns a running app and the domainmgr/zedrouter
// statuses that let doActivate run to the end.
func cpuPlacementFixture(verdict types.CPUPlacementStatus) (types.AppInstanceConfig,
	*types.AppInstanceStatus, *types.DomainStatus, *types.AppNetworkStatus) {

	uuidAndVersion := types.UUIDandVersion{
		UUID:    uuid.NewV5(uuid.NamespaceOID, "pinned-app"),
		Version: "1",
	}
	config := types.AppInstanceConfig{
		UUIDandVersion: uuidAndVersion,
		DisplayName:    "pinned-app",
		Activate:       true,
		FixedResources: types.VmConfig{VCpus: 4, Memory: 1024, CPUsPinned: true,
			CPUPlacement: types.CPUPlacementPolicy{Policy: types.CPUPolicyDedicated, Pinned: true}},
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
		UUIDandVersion:     uuidAndVersion,
		DisplayName:        "pinned-app",
		DomainName:         "pinned-app.1.1",
		State:              types.RUNNING,
		Activated:          true,
		CPUPlacementStatus: verdict,
	}
	ns := &types.AppNetworkStatus{
		UUIDandVersion: uuidAndVersion,
		DisplayName:    "pinned-app",
		Activated:      true,
	}
	return config, status, ds, ns
}

// TestDoActivate_CopiesCPUPlacementFromDomainStatus is the zedmanager link in
// the chain that carries a sub-optimal placement to the controller: domainmgr
// decides it on DomainStatus, zedmanager copies it onto AppInstanceStatus, and
// zedagent reports it. Without this copy the device works out that a repack
// would help and then keeps it to itself.
func TestDoActivate_CopiesCPUPlacementFromDomainStatus(t *testing.T) {
	config, status, ds, ns := cpuPlacementFixture(types.CPUPlacementStatusRepackAdvised)
	ds.RepackFor = []string{"other-app"}
	ds.OrderedCPUs = []uint32{2, 3}
	ds.ParkedCPUs = []uint32{6, 7}
	ctx := newCPUPlacementTestContext(t, ds, ns)

	doActivate(ctx, status.Key(), config, status)

	assert.Equal(t, types.CPUPlacementStatusRepackAdvised, status.CPUPlacementStatus)
	assert.Equal(t, ds.RepackFor, status.RepackFor)
	assert.True(t, status.AssignedCPUs.Equal(ds.CPUAssignment()))
	// It is status, not a failure: a workload placed sub-optimally keeps running.
	assert.False(t, status.HasError())
	assert.Equal(t, types.RUNNING, status.State)
}

// TestDoActivate_FollowsCPUPlacementBackToPlaced covers the other direction:
// once neighbouring workloads have moved, the same app is optimally placed and
// the advisory has to go away. A copy that only ever set "repack advised" would
// leave the controller nagging about a workload that is now placed as well as it
// can be.
func TestDoActivate_FollowsCPUPlacementBackToPlaced(t *testing.T) {
	config, status, ds, ns := cpuPlacementFixture(types.CPUPlacementStatusPlaced)
	status.CPUPlacementStatus = types.CPUPlacementStatusRepackAdvised
	ctx := newCPUPlacementTestContext(t, ds, ns)

	doActivate(ctx, status.Key(), config, status)

	assert.Equal(t, types.CPUPlacementStatusPlaced, status.CPUPlacementStatus)
}

// TestDoInactivate_ClearsCPUPlacement checks the teardown side: a torn-down
// workload holds no CPUs, so there is no placement left to judge. A stale
// "repack advised" would keep an advisory on the wire for an app that is not even
// running, and would survive into the next activation as a wrong starting value.
func TestDoInactivate_ClearsCPUPlacement(t *testing.T) {
	_, status, _, _ := cpuPlacementFixture(types.CPUPlacementStatusRepackAdvised)
	status.CPUPlacementStatus = types.CPUPlacementStatusRepackAdvised
	status.RepackFor = []string{"other-app"}
	status.AssignedCPUs = types.CPUAssignment{CPUs: []uint32{2, 3}}
	status.CPUWait = types.CPUWait{Holders: []string{"other-app"}, Since: time.Now()}
	// Nothing published for the app any more: domainmgr has removed the domain
	// and zedrouter the network.
	ctx := newCPUPlacementTestContext(t, nil, nil)

	changed, done := doInactivate(ctx, status.UUIDandVersion.UUID, status)

	assert.True(t, done)
	assert.True(t, changed)
	assert.Equal(t, types.CPUPlacementStatusUnspecified, status.CPUPlacementStatus)
	assert.Nil(t, status.RepackFor)
	assert.True(t, status.AssignedCPUs.Equal(types.CPUAssignment{}))
	assert.False(t, status.CPUWait.Waiting())
}

// A workload waiting for its planned CPUs has not booted, so the wait has to be
// mirrored before zedmanager waits for the domain to boot, or the controller
// never sees it.
func TestDoActivate_MirrorsACPUWaitBeforeTheDomainBoots(t *testing.T) {
	config, status, ds, ns := cpuPlacementFixture(types.CPUPlacementStatusUnspecified)
	ds.State = types.INSTALLED
	ds.Activated = false
	ds.CPUWait = types.CPUWait{Holders: []string{"other-app"},
		Since: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
	ctx := newCPUPlacementTestContext(t, ds, ns)

	doActivate(ctx, status.Key(), config, status)

	assert.True(t, status.CPUWait.Equal(ds.CPUWait))
	assert.False(t, status.HasError(), "a wait is not an error")
}

// A refused workload never boots, so its verdict has to be mirrored before
// zedmanager waits for the domain to boot, or the controller never learns why
// it is down.
func TestDoActivate_MirrorsARefusalBeforeTheDomainBoots(t *testing.T) {
	config, status, ds, ns := cpuPlacementFixture(types.CPUPlacementStatusNeedsRepack)
	ds.State = types.INSTALLED
	ds.Activated = false
	ds.SetErrorDescription(types.ErrorDescription{Error: "no room until a repack"})
	ctx := newCPUPlacementTestContext(t, ds, ns)

	doActivate(ctx, status.Key(), config, status)

	assert.Equal(t, types.CPUPlacementStatusNeedsRepack, status.CPUPlacementStatus)
}
