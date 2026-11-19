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

const rollbackTestSnapshot = "s1"

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
	}
	_, err := ctx.pubLocalAppInstanceConfig.Get(config.Key())
	assert.Error(t, err, "the config saved with the snapshot must no longer replace the one from the controller")
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
