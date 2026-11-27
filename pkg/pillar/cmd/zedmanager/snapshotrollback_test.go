// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	rollbackTestSnapshot            = "s1"
	rollbackTestMaxSnapshots uint32 = 3
	rollbackTestCounter      uint32 = 7
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
	config.Snapshot.Snapshots = []types.SnapshotDesc{{SnapshotID: rollbackTestSnapshot}}
	config.Snapshot.RollbackCmd.Counter = rollbackTestCounter
	volumeID := uuid.Must(uuid.FromString("22222222-2222-2222-2222-222222222222"))
	config.VolumeRefConfigList = []types.VolumeRefConfig{
		{VolumeID: volumeID, AppUUID: config.UUIDandVersion.UUID},
	}
	assert.NoError(t, newPub("zedagent", types.AppInstanceConfig{}).Publish(config.Key(), config))
	pubLocalConfig := newPub(agentName, types.AppInstanceConfig{})
	snapped := config
	snapped.UUIDandVersion.Version = "1"
	assert.NoError(t, pubLocalConfig.Publish(snapped.Key(), snapped))

	existing := existingSnapshot(rollbackTestSnapshot, config.UUIDandVersion.UUID)
	assert.NoError(t, newPub("volumemgr", types.VolumesSnapshotStatus{}).Publish(existing.Key(), existing))
	pubSnapConfig := newPub(agentName, types.VolumesSnapshotConfig{})
	for _, keep := range kept(existing) {
		assert.NoError(t, pubSnapConfig.Publish(keep.Key(), keep))
	}

	ctx := &zedmanagerContext{
		snapshotsRestored:         true,
		pubVolumesSnapConfig:      pubSnapConfig,
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
		subAppRuntimeStatus:       newSub("zedrouter", types.AppRuntimeStatus{}),
	}
	mapPublisher, err := objtonum.NewObjNumPublisher(log, ps, agentName, false, &types.UuidToNum{})
	assert.NoError(t, err)
	ctx.appToPurgeCounterMap = objtonum.NewPublishedMap(log, mapPublisher, "purgeCmdCounter", objtonum.AllKeys)
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
	refreshSnapshots(ctx, &status)
	publishAppInstanceStatus(ctx, &status)
	return ctx, config
}

// existingSnapshot is what volumemgr reports for a snapshot that was created.
func existingSnapshot(snapshotID string, app uuid.UUID) types.VolumesSnapshotStatus {
	return types.VolumesSnapshotStatus{
		SnapshotID:         snapshotID,
		AppUUID:            app,
		State:              types.VolumesSnapshotStateCreated,
		RollbackCountKnown: true,
	}
}

// useAppConfig makes zedagent publish the given config, and nothing else.
func useAppConfig(t *testing.T, ctx *zedmanagerContext, config types.AppInstanceConfig) {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedagent",
		TopicType: types.AppInstanceConfig{},
	})
	assert.NoError(t, err)
	assert.NoError(t, pub.Publish(config.Key(), config))
	ctx.subAppInstanceConfig, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceConfig{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, ctx.subAppInstanceConfig.Activate())
}

// rollbackAnswer is what volumemgr reports when it is through with a rollback
// to rollbackTestSnapshot, and the config that asked for it.
func rollbackAnswer(t *testing.T, ctx *zedmanagerContext, app uuid.UUID, failed bool) types.VolumesSnapshotStatus {
	t.Helper()
	answer := existingSnapshot(rollbackTestSnapshot, app)
	answer.RollbackCount = 1
	if failed {
		answer.State = types.VolumesSnapshotStateRollingBack
		answer.SetErrorWithSourceAndDescription(
			types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
	}
	useSnapshotState(t, ctx, kept(answer), []types.VolumesSnapshotStatus{answer})
	return answer
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

	reactToSnapshotRollback(ctx, rollbackAnswer(t, ctx, config.UUIDandVersion.UUID, true))

	published := lookupAppInstanceStatus(ctx, config.Key())
	if assert.NotNil(t, published) {
		assert.False(t, published.SnapStatus.RollbackInProgress)
		assert.Equal(t, "qemu-img failed",
			lookupSnapshot(published, rollbackTestSnapshot).Error.Error)
		assert.Equal(t, types.BringUp, published.PurgeInprogress, "the app must be started again")
	}
	_, err := ctx.pubLocalAppInstanceConfig.Get(config.Key())
	assert.Error(t, err, "the config saved with the snapshot must no longer replace the one from the controller")
}

// The error of a failed rollback goes away with a rollback that works.
func TestSuccessfulRollbackClearsTheSnapshotError(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.Snapshots[0].Error = types.ErrorDescription{Error: "qemu-img failed"}
	publishAppInstanceStatus(ctx, status)

	reactToSnapshotRollback(ctx, rollbackAnswer(t, ctx, config.UUIDandVersion.UUID, false))

	published := lookupAppInstanceStatus(ctx, config.Key())
	if assert.NotNil(t, published) {
		assert.Empty(t, lookupSnapshot(published, rollbackTestSnapshot).Error.Error)
	}
}

// zedmanager asks for a rollback with a RollbackCount in the config of the
// snapshot. The rollback is over when volumemgr has taken that count into the
// status and is not busy with the snapshot any more.
func TestRollbackEndsWithTheAnswerToItsRequest(t *testing.T) {
	for name, failed := range map[string]bool{"rollback that worked": false, "rollback that failed": true} {
		t.Run(name, func(t *testing.T) {
			ctx, config := newRollbackTestContext(t)
			app := config.UUIDandVersion.UUID
			inProgress := func() bool {
				return lookupAppInstanceStatus(ctx, config.Key()).SnapStatus.RollbackInProgress
			}
			request := kept(existingSnapshot(rollbackTestSnapshot, app))
			request[0].RollbackCount = 1
			report := func(st types.VolumesSnapshotStatus) {
				useSnapshotState(t, ctx, request, []types.VolumesSnapshotStatus{st})
				handleVolumesSnapshotStatusImpl(ctx, st, st.HasError())
			}

			// volumemgr says something of the snapshot before it took up
			// the request.
			report(existingSnapshot(rollbackTestSnapshot, app))
			assert.True(t, inProgress())

			busy := existingSnapshot(rollbackTestSnapshot, app)
			busy.State = types.VolumesSnapshotStateRollingBack
			busy.RollbackCount = 1
			report(busy)
			assert.True(t, inProgress())

			answer := rollbackAnswer(t, ctx, app, failed)
			// The app is still running, so zedmanager has not asked yet.
			status := lookupAppInstanceStatus(ctx, config.Key())
			status.SnapStatus.HasRollbackRequest = true
			publishAppInstanceStatus(ctx, status)
			report(answer)
			assert.True(t, inProgress(), "this is the outcome of an earlier rollback")

			status.SnapStatus.HasRollbackRequest = false
			publishAppInstanceStatus(ctx, status)
			report(answer)
			assert.False(t, inProgress())
		})
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

	reactToSnapshotRollback(ctx, rollbackAnswer(t, ctx, config.UUIDandVersion.UUID, false))

	assert.Nil(t, lookupAppInstanceStatus(ctx, config.Key()), "the app must be removed")
	_, err = ctx.pubLocalAppInstanceConfig.Get(config.Key())
	assert.Error(t, err)
}

// An app that is deleted while a purge brings it down has to be removed once
// it is down: there is no config to go on with.
func TestAppDeletedDuringPurgeIsRemoved(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	// Persistent subscriptions were filled at Activate; drop the configs there.
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	noConfig := func(agent string) pubsub.Subscription {
		sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
			AgentName:   agent,
			MyAgentName: agentName,
			TopicImpl:   types.AppInstanceConfig{},
			Persistent:  true,
		})
		assert.NoError(t, err)
		assert.NoError(t, sub.Activate())
		return sub
	}
	ctx.subAppInstanceConfig = noConfig("zedagent")
	ctx.subLocalAppInstanceConfig = noConfig(agentName)
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.RollbackInProgress = false
	status.PurgeInprogress = types.BringDown

	removeAIStatus(ctx, status)

	assert.Nil(t, lookupAppInstanceStatus(ctx, config.Key()), "the app must be removed")
}

// What doUpdate changes once the rollback is over has to be published; here
// it is the phase of the purge that the rollback is part of.
func TestRollbackResultIsPublished(t *testing.T) {
	ctx, config := newRollbackTestContext(t)

	reactToSnapshotRollback(ctx, rollbackAnswer(t, ctx, config.UUIDandVersion.UUID, false))

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

	assert.Equal(t, 1, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
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

		assert.Zero(t, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
		assert.True(t, status.SnapStatus.HasRollbackRequest)
	})
	t.Run("the domain runs", func(t *testing.T) {
		ctx, config := newRollbackTestContext(t)
		status := lookupAppInstanceStatus(ctx, config.Key())
		status.SnapStatus.HasRollbackRequest = true
		useDomainStatus(t, ctx, types.DomainStatus{UUIDandVersion: status.UUIDandVersion, Activated: true})

		doUpdate(ctx, config, status)

		assert.Zero(t, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
		assert.True(t, status.SnapStatus.HasRollbackRequest)
	})
	t.Run("domainmgr is starting the domain", func(t *testing.T) {
		ctx, config := newRollbackTestContext(t)
		status := lookupAppInstanceStatus(ctx, config.Key())
		status.SnapStatus.HasRollbackRequest = true
		useDomainStatus(t, ctx, types.DomainStatus{UUIDandVersion: status.UUIDandVersion, State: types.BOOTING})

		doUpdate(ctx, config, status)

		assert.Zero(t, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
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

// volumemgr rolls back when the config of the snapshot has a higher count
// than its status, and keeps the count with the snapshot. So the count is the
// counter of the controller, which tells after a reboot whether the rollback
// was done. A controller that uses a counter again still gets its rollback.
func TestRollbackRequestIsAboveTheCountOfTheSnapshot(t *testing.T) {
	requested := func(t *testing.T, counter uint32, done int) int {
		ctx, config := newRollbackTestContext(t)
		st := existingSnapshot(rollbackTestSnapshot, config.UUIDandVersion.UUID)
		st.RollbackCount = done
		useSnapshotState(t, ctx, kept(st), []types.VolumesSnapshotStatus{st})
		status := lookupAppInstanceStatus(ctx, config.Key())
		status.SnapStatus.RollbackCmdCounter = counter
		assert.NoError(t, triggerRollback(ctx, status))
		return snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount
	}
	assert.Equal(t, 7, requested(t, 7, 0))
	assert.Equal(t, 7, requested(t, 7, 6))
	assert.Equal(t, 2, requested(t, 1, 1), "the same counter again")
	assert.Equal(t, 8, requested(t, 3, 7))
}

// A rollback is only possible to a snapshot that all volumes have. If there
// is none when the app is down, the rollback ends there, and the app goes on
// with the config of the controller.
func TestRollbackToASnapshotThatCannotBeRolledBackTo(t *testing.T) {
	for name, change := range map[string]func(ctx *zedmanagerContext, st types.VolumesSnapshotStatus){
		"it is gone": func(ctx *zedmanagerContext, _ types.VolumesSnapshotStatus) {
			useSnapshotState(t, ctx, nil, nil)
		},
		"its creation failed": func(ctx *zedmanagerContext, st types.VolumesSnapshotStatus) {
			st.State = types.VolumesSnapshotStateCreating
			st.SetErrorWithSourceAndDescription(
				types.ErrorDescription{Error: "no space"}, types.VolumesSnapshotStatus{})
			useSnapshotState(t, ctx, kept(st), []types.VolumesSnapshotStatus{st})
		},
		"it is being deleted": func(ctx *zedmanagerContext, st types.VolumesSnapshotStatus) {
			st.State = types.VolumesSnapshotStateDeleting
			st.SetErrorWithSourceAndDescription(
				types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
			useSnapshotState(t, ctx, nil, []types.VolumesSnapshotStatus{st})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, config := newRollbackTestContext(t)
			change(ctx, existingSnapshot(rollbackTestSnapshot, config.UUIDandVersion.UUID))
			status := lookupAppInstanceStatus(ctx, config.Key())
			status.SnapStatus.HasRollbackRequest = true

			doUpdate(ctx, config, status)

			assert.False(t, status.SnapStatus.HasRollbackRequest)
			assert.False(t, status.SnapStatus.RollbackInProgress, "nothing would end the rollback")
			if request := snapshotConfig(ctx, rollbackTestSnapshot); request != nil {
				assert.Zero(t, request.RollbackCount, "volumemgr would not answer")
			}
			_, err := ctx.pubLocalAppInstanceConfig.Get(config.Key())
			assert.Error(t, err, "the config saved with the snapshot is not what the app goes on with")
			assert.Equal(t, types.BringUp, status.PurgeInprogress)
		})
	}
}

// The controller can ask for a rollback to a snapshot that is none: the
// creation failed, or the deletion has started. zedmanager does not bring the
// app down for that.
func TestRollbackIsNotStartedToASnapshotThatCannotBeRolledBackTo(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	config.Snapshot.ActiveSnapshot = rollbackTestSnapshot
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.RollbackInProgress = false
	failed := existingSnapshot(rollbackTestSnapshot, config.UUIDandVersion.UUID)
	failed.State = types.VolumesSnapshotStateCreating
	failed.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "no space"}, types.VolumesSnapshotStatus{})
	useSnapshotState(t, ctx, kept(failed), []types.VolumesSnapshotStatus{failed})

	startRollback(ctx, config, status)

	assert.Contains(t, status.Error, "Cannot roll back to snapshot")
	// The controller learns of it from the published status only.
	if published := lookupAppInstanceStatus(ctx, status.Key()); assert.NotNil(t, published) {
		assert.Contains(t, published.Error, "Cannot roll back to snapshot")
	}
	assert.False(t, status.SnapStatus.HasRollbackRequest)
	assert.False(t, status.SnapStatus.RollbackInProgress)
}

// A rollback that was asked for and not done before a reboot has to run after
// it. The status of the snapshot, which volumemgr restores from its record,
// has the count of the last rollback to it that volumemgr took up.
func TestRollbackLeftOverFromBeforeAReboot(t *testing.T) {
	leftOver := func(t *testing.T, change func(config *types.AppInstanceConfig, st *types.VolumesSnapshotStatus)) bool {
		ctx, config := newRollbackTestContext(t)
		config.Snapshot.ActiveSnapshot = rollbackTestSnapshot
		config.Snapshot.RollbackCmd.Counter = 7
		st := existingSnapshot(rollbackTestSnapshot, config.UUIDandVersion.UUID)
		st.RollbackCount = 6
		change(&config, &st)
		useSnapshotState(t, ctx, kept(st), []types.VolumesSnapshotStatus{st})

		askForRollbackLeftOver(ctx, config)

		// volumemgr rolls back when the config has the higher count.
		asked := snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount > st.RollbackCount
		assert.Equal(t, asked, rollbackLeftOver(ctx, config))
		if asked {
			assert.Equal(t, 7, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
		}
		return asked
	}
	assert.True(t, leftOver(t, func(*types.AppInstanceConfig, *types.VolumesSnapshotStatus) {}))
	assert.True(t, leftOver(t, func(_ *types.AppInstanceConfig, st *types.VolumesSnapshotStatus) {
		st.State = types.VolumesSnapshotStateRollingBack
		st.SetErrorWithSourceAndDescription(
			types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
	}), "the rollback that failed was an earlier one")
	assert.False(t, leftOver(t, func(_ *types.AppInstanceConfig, st *types.VolumesSnapshotStatus) {
		st.RollbackCount = 7
	}), "volumemgr took it up: it is done, has failed, or goes on by itself")
	assert.False(t, leftOver(t, func(_ *types.AppInstanceConfig, st *types.VolumesSnapshotStatus) {
		st.RollbackCountKnown = false
	}), "the app may have been rolled back to it long ago")
	assert.False(t, leftOver(t, func(_ *types.AppInstanceConfig, st *types.VolumesSnapshotStatus) {
		st.State = types.VolumesSnapshotStateCreating
	}), "not a snapshot that all volumes have")
	assert.False(t, leftOver(t, func(config *types.AppInstanceConfig, _ *types.VolumesSnapshotStatus) {
		config.Snapshot.ActiveSnapshot = ""
	}))
	assert.False(t, leftOver(t, func(config *types.AppInstanceConfig, _ *types.VolumesSnapshotStatus) {
		config.Snapshot.Snapshots = nil
	}), "a snapshot that is to be deleted")
	assert.False(t, leftOver(t, func(config *types.AppInstanceConfig, _ *types.VolumesSnapshotStatus) {
		config.Snapshot.ActiveSnapshot = "unknown"
		config.Snapshot.Snapshots = []types.SnapshotDesc{{SnapshotID: "unknown"}}
	}))
}

// What volumemgr did before the reboot is only known once it has published
// its snapshots. Until then the app must not start: a rollback may have been
// cut off, or a snapshot may be due for deletion.
func TestAppWaitsUntilVolumemgrHasToldWhichSnapshotsExist(t *testing.T) {
	ctx, config := newRollbackTestContext(t)
	config.Activate = true
	ctx.snapshotsRestored = false
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.RollbackInProgress = false
	status.SnapStatus.HasRollbackRequest = true
	status.PurgeInprogress = types.NotInprogress

	assert.False(t, doUpdate(ctx, config, status))
	assert.True(t, status.SnapStatus.HasRollbackRequest, "there is nothing to ask of volumemgr yet")
	assert.Zero(t, snapshotConfig(ctx, rollbackTestSnapshot).RollbackCount)
	assert.Empty(t, ctx.pubAppNetworkConfig.GetAll())
}
