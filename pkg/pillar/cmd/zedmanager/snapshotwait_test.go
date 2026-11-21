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
// zedmanager and the given snapshot statuses as volumemgr. No domain has a
// status.
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
		pubVolumesSnapConfig: pubSnapConfig,
		subVolumesSnapStatus: subSnapStatus,
		subDomainStatus:      subDomainStatus,
	}
}

func TestSnapshotOpInProgress(t *testing.T) {
	app := uuid.Must(uuid.FromString(appA))
	other := uuid.Must(uuid.FromString(appB))
	config := func(id string, appUUID uuid.UUID) types.VolumesSnapshotConfig {
		return types.VolumesSnapshotConfig{SnapshotID: id, AppUUID: appUUID,
			Action: types.VolumesSnapshotCreate}
	}
	status := func(id string, appUUID uuid.UUID) types.VolumesSnapshotStatus {
		return types.VolumesSnapshotStatus{SnapshotID: id, AppUUID: appUUID,
			ResultOfAction: types.VolumesSnapshotCreate}
	}

	tests := []struct {
		name     string
		configs  []types.VolumesSnapshotConfig
		statuses []types.VolumesSnapshotStatus
		want     bool
	}{
		{name: "no snapshots"},
		{
			name:    "creation requested, no answer yet",
			configs: []types.VolumesSnapshotConfig{config("s1", app)},
			want:    true,
		},
		{
			name:     "creation answered",
			configs:  []types.VolumesSnapshotConfig{config("s1", app)},
			statuses: []types.VolumesSnapshotStatus{status("s1", app)},
		},
		{
			name:     "deletion requested, snapshot still there",
			statuses: []types.VolumesSnapshotStatus{status("s1", app)},
			want:     true,
		},
		{
			name:     "old snapshot being deleted while a new one exists",
			configs:  []types.VolumesSnapshotConfig{config("s2", app)},
			statuses: []types.VolumesSnapshotStatus{status("s1", app), status("s2", app)},
			want:     true,
		},
		{
			name:     "another app's snapshots do not count",
			configs:  []types.VolumesSnapshotConfig{config("s1", other)},
			statuses: []types.VolumesSnapshotStatus{status("s2", other)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newSnapshotWaitTestContext(t, tt.configs, tt.statuses)
			assert.Equal(t, tt.want, snapshotOpInProgress(ctx, app))
		})
	}
}

// doUpdate must not touch the app while a snapshot is in flight. Without one
// it goes on to doInstall, which is visible here as a state change.
func TestDoUpdateWaitsForSnapshot(t *testing.T) {
	app := uuid.Must(uuid.FromString(appA))
	uv := types.UUIDandVersion{UUID: app, Version: "1"}
	config := types.AppInstanceConfig{UUIDandVersion: uv, Activate: true}
	inFlight := []types.VolumesSnapshotConfig{
		{SnapshotID: "s1", AppUUID: app, Action: types.VolumesSnapshotCreate},
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
		{SnapshotID: "s1", AppUUID: app, Action: types.VolumesSnapshotCreate},
	}
	status := types.AppInstanceStatus{
		UUIDandVersion:  types.UUIDandVersion{UUID: app, Version: "1"},
		PurgeInprogress: types.BringDown,
	}
	ctx := newSnapshotWaitTestContext(t, inFlight, nil)
	assert.NotPanics(t, func() { removeAIStatus(ctx, &status) })
	assert.Equal(t, types.BringDown, status.PurgeInprogress)
}
