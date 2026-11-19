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

const (
	rollbackTestSnapshot            = "s1"
	rollbackTestMaxSnapshots uint32 = 3
)

// newRollbackTestContext publishes an app that waits for volumemgr to roll it
// back to rollbackTestSnapshot: purged, domain down, running on the config
// that was saved with the snapshot.
func newRollbackTestContext(t *testing.T) (*zedmanagerContext, types.AppInstanceConfig) {
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
	// Persistent makes Activate fill the subscription synchronously.
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

	config := types.AppInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{
			UUID:    uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111")),
			Version: "2",
		},
	}
	config.Snapshot.MaxSnapshots = rollbackTestMaxSnapshots
	volumeID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	config.VolumeRefConfigList = []types.VolumeRefConfig{
		{VolumeID: volumeID, AppUUID: config.UUIDandVersion.UUID},
	}
	assert.NoError(t, newPub("zedagent", types.AppInstanceConfig{}).Publish(config.Key(), config))
	pubLocalConfig := newPub(agentName, types.AppInstanceConfig{})
	snapped := config
	snapped.UUIDandVersion.Version = "1"
	assert.NoError(t, pubLocalConfig.Publish(snapped.Key(), snapped))

	ctx := &zedmanagerContext{
		pubVolumesSnapConfig:      newPub(agentName, types.VolumesSnapshotConfig{}),
		subVolumesSnapStatus:      newSub("volumemgr", types.VolumesSnapshotStatus{}),
		pubAppInstanceStatus:      newPub(agentName, types.AppInstanceStatus{}),
		pubLocalAppInstanceConfig: pubLocalConfig,
		subAppInstanceConfig:      newSub("zedagent", types.AppInstanceConfig{}),
		subLocalAppInstanceConfig: newSub(agentName, types.AppInstanceConfig{}),
		subDomainStatus:           newSub("domainmgr", types.DomainStatus{}),
		subVolumeRefStatus:        newSub("volumemgr", types.VolumeRefStatus{}),
		pubAppInstanceSummary:     newPub(agentName, types.AppInstanceSummary{}),
		pubDomainConfig:           newPub(agentName, types.DomainConfig{}),
		pubAppNetworkConfig:       newPub(agentName, types.AppNetworkConfig{}),
		pubVolumeRefConfig:        newPub(agentName, types.VolumeRefConfig{}),
		subAppNetworkStatus:       newSub("zedrouter", types.AppNetworkStatus{}),
	}
	status := types.AppInstanceStatus{
		UUIDandVersion:  snapped.UUIDandVersion,
		State:           types.HALTED,
		NoBootPriority:  true,
		PurgeInprogress: types.RecreateVolumes,
		VolumeRefStatusList: []types.VolumeRefStatus{{
			VolumeID: volumeID,
			AppUUID:  config.UUIDandVersion.UUID,
			State:    types.CREATED_VOLUME,
		}},
	}
	status.SnapStatus.RollbackInProgress = true
	status.SnapStatus.ActiveSnapshot = rollbackTestSnapshot
	status.SnapStatus.AvailableSnapshots = []types.SnapshotInstanceStatus{{
		Snapshot:      types.SnapshotDesc{SnapshotID: rollbackTestSnapshot},
		AppInstanceID: config.UUIDandVersion.UUID,
	}}
	publishAppInstanceStatus(ctx, &status)
	return ctx, config
}

// useDomainStatus makes domainmgr report the given status to ctx.
func useDomainStatus(t *testing.T, ctx *zedmanagerContext, domain types.DomainStatus) {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "domainmgr",
		TopicType: types.DomainStatus{},
	})
	assert.NoError(t, err)
	assert.NoError(t, pub.Publish(domain.Key(), domain))
	ctx.subDomainStatus, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainStatus{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, ctx.subDomainStatus.Activate())
}

// A rollback that volumemgr could not do must not leave the app waiting for
// it: nothing else is going to end the rollback.
func TestFailedRollbackDoesNotKeepTheAppDown(t *testing.T) {
	ctx, config := newRollbackTestContext(t)

	result := types.VolumesSnapshotStatus{
		SnapshotID:     rollbackTestSnapshot,
		AppUUID:        config.UUIDandVersion.UUID,
		ResultOfAction: types.VolumesSnapshotRollback,
	}
	result.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
	reactToSnapshotRollback(ctx, result)

	published := lookupAppInstanceStatus(ctx, config.Key())
	if assert.NotNil(t, published) {
		assert.False(t, published.SnapStatus.RollbackInProgress)
		assert.Equal(t, "qemu-img failed",
			published.SnapStatus.AvailableSnapshots[0].Error.Error)
		assert.Equal(t, types.BringUp, published.PurgeInprogress, "the app must be started again")
	}
	_, err := ctx.pubLocalAppInstanceConfig.Get(config.Key())
	assert.Error(t, err, "the config saved with the snapshot must no longer replace the one from the controller")
}

// The error of a failed rollback goes away with a rollback that works.
func TestSuccessfulRollbackClearsTheSnapshotError(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.AvailableSnapshots[0].Error = types.ErrorDescription{Error: "qemu-img failed"}
	publishAppInstanceStatus(ctx, status)

	reactToSnapshotRollback(ctx, types.VolumesSnapshotStatus{
		SnapshotID:     rollbackTestSnapshot,
		AppUUID:        config.UUIDandVersion.UUID,
		ResultOfAction: types.VolumesSnapshotRollback,
	})

	published := lookupAppInstanceStatus(ctx, config.Key())
	if assert.NotNil(t, published) {
		assert.Empty(t, published.SnapStatus.AvailableSnapshots[0].Error.Error)
	}
}

// The app can be deleted while its rollback is pending. The answer from
// volumemgr must then not bring the device down, and the app must not be left
// behind half removed.
func TestRollbackResultForDeletedApp(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	// Persistent subscriptions were filled at Activate; drop the config there.
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceConfig{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, sub.Activate())
	ctx.subAppInstanceConfig = sub

	reactToSnapshotRollback(ctx, types.VolumesSnapshotStatus{
		SnapshotID:     rollbackTestSnapshot,
		AppUUID:        config.UUIDandVersion.UUID,
		ResultOfAction: types.VolumesSnapshotRollback,
	})

	assert.Nil(t, lookupAppInstanceStatus(ctx, config.Key()), "the app must be removed")
	_, err = ctx.pubLocalAppInstanceConfig.Get(config.Key())
	assert.Error(t, err)
}

// What doUpdate changes once the rollback is over has to be published; here
// it is the phase of the purge that the rollback is part of.
func TestRollbackResultIsPublished(t *testing.T) {
	ctx, config := newRollbackTestContext(t)

	reactToSnapshotRollback(ctx, types.VolumesSnapshotStatus{
		SnapshotID:     rollbackTestSnapshot,
		AppUUID:        config.UUIDandVersion.UUID,
		ResultOfAction: types.VolumesSnapshotRollback,
	})

	published := lookupAppInstanceStatus(ctx, config.Key())
	if assert.NotNil(t, published) {
		assert.False(t, published.SnapStatus.RollbackInProgress)
		assert.Equal(t, types.BringUp, published.PurgeInprogress)
	}
}

// An app that was not started since boot has no DomainStatus. A rollback
// requested for it must still be handed to volumemgr.
func TestRollbackIsTriggeredWithoutDomain(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.HasRollbackRequest = true

	assert.True(t, doUpdate(ctx, config, status))

	published := lookupVolumesSnapshotConfig(ctx, rollbackTestSnapshot)
	if assert.NotNil(t, published) {
		assert.Equal(t, types.VolumesSnapshotRollback, published.Action)
	}
	assert.False(t, status.SnapStatus.HasRollbackRequest)
}

// qemu-img must not get the disk images while the domain runs or is about to.
func TestRollbackWaitsForTheDomainToBeDown(t *testing.T) {
	t.Run("zedmanager is activating the app", func(t *testing.T) {
		ctx, config := newRollbackTestContext(t)
		status := lookupAppInstanceStatus(ctx, config.Key())
		status.SnapStatus.HasRollbackRequest = true
		status.ActivateInprogress = true

		doUpdate(ctx, config, status)

		assert.Nil(t, lookupVolumesSnapshotConfig(ctx, rollbackTestSnapshot))
		assert.True(t, status.SnapStatus.HasRollbackRequest)
	})
	t.Run("the domain runs", func(t *testing.T) {
		ctx, config := newRollbackTestContext(t)
		status := lookupAppInstanceStatus(ctx, config.Key())
		status.SnapStatus.HasRollbackRequest = true
		useDomainStatus(t, ctx, types.DomainStatus{UUIDandVersion: status.UUIDandVersion, Activated: true})

		doUpdate(ctx, config, status)

		assert.Nil(t, lookupVolumesSnapshotConfig(ctx, rollbackTestSnapshot))
		assert.True(t, status.SnapStatus.HasRollbackRequest)
	})
}

// The config saved with a snapshot is as old as the snapshot. A rollback must
// go by the snapshot limit that is valid now, or it flags snapshots for
// deletion that the current limit allows.
func TestRollbackConfigKeepsCurrentSnapshotLimit(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	saved := config
	saved.Snapshot.MaxSnapshots = 1

	fixed, err := fixupAppInstanceConfig(ctx, status, &saved)
	assert.NoError(t, err)
	assert.Equal(t, rollbackTestMaxSnapshots, fixed.Snapshot.MaxSnapshots)
}
