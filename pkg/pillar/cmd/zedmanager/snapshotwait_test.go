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

// newSnapshotWaitTestContext publishes the given snapshot configs as
// zedmanager and the given snapshot statuses as volumemgr, which has told
// that these are all. No domain has a status.
func newSnapshotWaitTestContext(t *testing.T, configs []types.VolumesSnapshotConfig,
	statuses []types.VolumesSnapshotStatus) *zedmanagerContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pubSnapConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumesSnapshotConfig{},
	})
	assert.NoError(t, err)
	for _, c := range configs {
		assert.NoError(t, pubSnapConfig.Publish(c.Key(), c))
	}

	volumemgrPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "volumemgr",
		TopicType: types.VolumesSnapshotStatus{},
	})
	assert.NoError(t, err)
	for _, s := range statuses {
		assert.NoError(t, volumemgrPub.Publish(s.Key(), s))
	}

	// Persistent makes Activate fill the subscription synchronously.
	subSnapStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "volumemgr",
		MyAgentName: agentName,
		TopicImpl:   types.VolumesSnapshotStatus{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, subSnapStatus.Activate())

	subDomainStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "domainmgr",
		MyAgentName: agentName,
		TopicImpl:   types.DomainStatus{},
		Persistent:  true,
	})
	assert.NoError(t, err)
	assert.NoError(t, subDomainStatus.Activate())

	return &zedmanagerContext{
		snapshotsRestored:    true,
		pubVolumesSnapConfig: pubSnapConfig,
		subVolumesSnapStatus: subSnapStatus,
		subDomainStatus:      subDomainStatus,
	}
}

// kept returns the configs with which zedmanager keeps the given snapshots.
func kept(statuses ...types.VolumesSnapshotStatus) []types.VolumesSnapshotConfig {
	var configs []types.VolumesSnapshotConfig
	for _, st := range statuses {
		configs = append(configs, types.VolumesSnapshotConfig{
			SnapshotID: st.SnapshotID, AppUUID: st.AppUUID, RollbackCount: st.RollbackCount,
		})
	}
	return configs
}

// The app has to stay down from the moment zedmanager asks for something, by
// publishing a config, changing it or taking it away, until volumemgr is
// through with it. An action that failed leaves the snapshot in its state
// with the error, and the app can go on.
func TestSnapshotOpInProgress(t *testing.T) {
	app := uuid.Must(uuid.FromString(appA))
	other := uuid.Must(uuid.FromString(appB))
	const (
		creating    = types.VolumesSnapshotStateCreating
		created     = types.VolumesSnapshotStateCreated
		rollingBack = types.VolumesSnapshotStateRollingBack
		deleting    = types.VolumesSnapshotStateDeleting
	)
	config := func(rollbackCount int) []types.VolumesSnapshotConfig {
		return []types.VolumesSnapshotConfig{{SnapshotID: "s1", AppUUID: app, RollbackCount: rollbackCount}}
	}
	status := func(state types.VolumesSnapshotState, rollbackCount int, failed bool) []types.VolumesSnapshotStatus {
		st := types.VolumesSnapshotStatus{SnapshotID: "s1", AppUUID: app, State: state, RollbackCount: rollbackCount}
		if failed {
			st.SetErrorWithSourceAndDescription(
				types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
		}
		return []types.VolumesSnapshotStatus{st}
	}

	tests := []struct {
		name     string
		configs  []types.VolumesSnapshotConfig
		statuses []types.VolumesSnapshotStatus
		want     bool
	}{
		{name: "no snapshots"},
		{"snapshot that is kept", config(0), status(created, 0, false), false},

		{"creation asked for", config(0), nil, true},
		{"creation in the worker or waiting for it", config(0), status(creating, 0, false), true},
		{"creation failed", config(0), status(creating, 0, true), false},

		{"rollback asked for", config(2), status(created, 1, false), true},
		{"rollback in the worker or waiting for it", config(2), status(rollingBack, 2, false), true},
		{"rollback done", config(2), status(created, 2, false), false},
		{"rollback failed", config(2), status(rollingBack, 2, true), false},
		{"another rollback asked for after one that failed", config(3), status(rollingBack, 2, true), true},
		{"rollback that volumemgr would not do", config(1), status(creating, 0, true), false},

		{"deletion asked for", nil, status(created, 0, false), true},
		{"deletion asked for of what a failed creation left", nil, status(creating, 0, true), true},
		{"deletion in the worker or waiting for it", nil, status(deleting, 0, false), true},
		{"deletion failed", nil, status(deleting, 0, true), false},

		{
			name:    "another app's snapshots do not count",
			configs: []types.VolumesSnapshotConfig{{SnapshotID: "s1", AppUUID: other}},
			statuses: []types.VolumesSnapshotStatus{
				{SnapshotID: "s2", AppUUID: other, State: deleting},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newSnapshotWaitTestContext(t, tt.configs, tt.statuses)
			assert.Equal(t, tt.want, snapshotOpInProgress(ctx, app))
		})
	}
	t.Run("before volumemgr has told which snapshots exist", func(t *testing.T) {
		ctx := newSnapshotWaitTestContext(t, nil, nil)
		ctx.snapshotsRestored = false
		assert.True(t, snapshotOpInProgress(ctx, app), "one of them may be due for a rollback or a deletion")
	})
}

// doUpdate must not touch the app while a snapshot is in flight. Without one
// it goes on to doInstall, which is visible here as a state change.
func TestDoUpdateWaitsForSnapshot(t *testing.T) {
	app := uuid.Must(uuid.FromString(appA))
	uv := types.UUIDandVersion{UUID: app, Version: "1"}
	config := types.AppInstanceConfig{UUIDandVersion: uv, Activate: true}
	inFlight := []types.VolumesSnapshotConfig{
		{SnapshotID: "s1", AppUUID: app},
	}

	status := types.AppInstanceStatus{UUIDandVersion: uv, State: types.INSTALLED}
	ctx := newSnapshotWaitTestContext(t, inFlight, nil)
	assert.False(t, doUpdate(ctx, config, &status))
	assert.Equal(t, types.INSTALLED, status.State)

	status = types.AppInstanceStatus{UUIDandVersion: uv, State: types.INSTALLED}
	ctx = newSnapshotWaitTestContext(t, nil, nil)
	assert.True(t, doUpdate(ctx, config, &status))
	assert.NotEqual(t, types.INSTALLED, status.State)
}

// A purge must not go past bringing the app down while a snapshot is in
// flight; going on would end in RecreateVolumes.
func TestRemoveAIStatusWaitsForSnapshot(t *testing.T) {
	app := uuid.Must(uuid.FromString(appA))
	inFlight := []types.VolumesSnapshotConfig{
		{SnapshotID: "s1", AppUUID: app},
	}
	status := types.AppInstanceStatus{
		UUIDandVersion:  types.UUIDandVersion{UUID: app, Version: "1"},
		PurgeInprogress: types.BringDown,
	}
	ctx := newSnapshotWaitTestContext(t, inFlight, nil)
	assert.NotPanics(t, func() { removeAIStatus(ctx, &status) })
	assert.Equal(t, types.BringDown, status.PurgeInprogress)
}

// newIdleAppTestContext publishes an app that is down after a purge and has
// nothing left to wait for but the given snapshot configs and statuses.
func newIdleAppTestContext(t *testing.T, configs []types.VolumesSnapshotConfig,
	statuses []types.VolumesSnapshotStatus) (*zedmanagerContext, types.AppInstanceConfig) {
	t.Helper()
	ctx, config := newRollbackTestContext(t)
	status := lookupAppInstanceStatus(ctx, config.Key())
	status.SnapStatus.RollbackInProgress = false
	publishAppInstanceStatus(ctx, status)
	useSnapshotState(t, ctx, configs, statuses)
	return ctx, config
}

func useSnapshotState(t *testing.T, ctx *zedmanagerContext, configs []types.VolumesSnapshotConfig,
	statuses []types.VolumesSnapshotStatus) {
	t.Helper()
	snap := newSnapshotWaitTestContext(t, configs, statuses)
	ctx.pubVolumesSnapConfig = snap.pubVolumesSnapConfig
	ctx.subVolumesSnapStatus = snap.subVolumesSnapStatus
}

// Nothing but the answer from volumemgr ends the wait, so the answer has to
// take the app up again.
func TestSnapshotAnswerResumesTheApp(t *testing.T) {
	app := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	created := existingSnapshot("s2", app)
	deleteFailed := created
	deleteFailed.State = types.VolumesSnapshotStateDeleting
	deleteFailed.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
	tests := []struct {
		name string
		// what is published while volumemgr works, and once it has answered
		pendingConfigs, answeredConfigs   []types.VolumesSnapshotConfig
		pendingStatuses, answeredStatuses []types.VolumesSnapshotStatus
		// the status that volumemgr publishes, or the one it takes away
		answer  types.VolumesSnapshotStatus
		removed bool
	}{
		{
			name:             "creation",
			pendingConfigs:   kept(created),
			answeredConfigs:  kept(created),
			answeredStatuses: []types.VolumesSnapshotStatus{created},
			answer:           created,
		},
		{
			name:            "deletion",
			pendingStatuses: []types.VolumesSnapshotStatus{created},
			answer:          created,
			removed:         true,
		},
		{
			name:             "deletion that failed",
			pendingStatuses:  []types.VolumesSnapshotStatus{created},
			answeredStatuses: []types.VolumesSnapshotStatus{deleteFailed},
			answer:           deleteFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, appConfig := newIdleAppTestContext(t, tt.pendingConfigs, tt.pendingStatuses)
			updateAIStatusUUID(ctx, appConfig.Key())
			assert.Equal(t, types.RecreateVolumes, lookupAppInstanceStatus(ctx, appConfig.Key()).PurgeInprogress)

			useSnapshotState(t, ctx, tt.answeredConfigs, tt.answeredStatuses)
			if tt.removed {
				handleVolumesSnapshotStatusDelete(ctx, tt.answer.Key(), tt.answer)
			} else {
				handleVolumesSnapshotStatusImpl(ctx, tt.answer, tt.answer.HasError())
			}
			assert.Equal(t, types.BringUp, lookupAppInstanceStatus(ctx, appConfig.Key()).PurgeInprogress)
		})
	}
}

// The wait also has to hold for an operation that the same call started.
func TestAppWaitsForTheSnapshotOperationItStarts(t *testing.T) {
	app := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))

	t.Run("deletion in doUpdate", func(t *testing.T) {
		// The config of the app does not list s2.
		unlisted := existingSnapshot("s2", app)
		ctx, appConfig := newIdleAppTestContext(t, kept(unlisted), []types.VolumesSnapshotStatus{unlisted})
		ctx.configFromController = true
		status := lookupAppInstanceStatus(ctx, appConfig.Key())

		doUpdate(ctx, appConfig, status)

		assert.Nil(t, snapshotConfig(ctx, "s2"), "the deletion is asked for by taking the config away")
		assert.Equal(t, types.RecreateVolumes, status.PurgeInprogress)
	})
	t.Run("creation in a purge", func(t *testing.T) {
		config := types.VolumesSnapshotConfig{SnapshotID: "s2", AppUUID: app}
		ctx, appConfig := newIdleAppTestContext(t, nil, nil)
		status := lookupAppInstanceStatus(ctx, appConfig.Key())
		useDomainStatus(t, ctx, types.DomainStatus{UUIDandVersion: status.UUIDandVersion})
		status.PurgeInprogress = types.BringDown
		status.SnapStatus.SnapshotTakenType = types.SnapshotImmediate
		status.SnapStatus.PreparedVolumesSnapshotConfigs = []types.VolumesSnapshotConfig{config}

		removeAIStatus(ctx, status)

		assert.NotNil(t, snapshotConfig(ctx, "s2"), "the creation must be asked for")
		assert.Empty(t, status.SnapStatus.PreparedVolumesSnapshotConfigs, "and only once")
		assert.Equal(t, types.BringDown, status.PurgeInprogress)
	})
}
