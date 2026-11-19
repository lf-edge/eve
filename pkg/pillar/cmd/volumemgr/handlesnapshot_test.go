// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// pubsub does not deliver a status that is published unchanged, so every
// rollback has to leave a status that differs from the one before, also when
// the outcome is the same. A status that carries the error of an earlier
// attempt must not make a rollback that worked look failed.
func TestEveryRollbackPublishesANewStatus(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumesSnapshotStatus{},
	})
	assert.NoError(t, err)
	ctx := &volumemgrContext{pubVolumesSnapStatus: pub}

	app := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	// No volumes, so the rollback itself has nothing to do and succeeds.
	failed := types.VolumesSnapshotStatus{
		SnapshotID:         "s1",
		AppUUID:            app,
		VolumeSnapshotMeta: map[string]interface{}{},
		ResultOfAction:     types.VolumesSnapshotRollback,
	}
	failed.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
	publishVolumesSnapshotStatus(ctx, &failed)

	config := types.VolumesSnapshotConfig{
		SnapshotID: "s1",
		AppUUID:    app,
		Action:     types.VolumesSnapshotRollback,
	}
	published := func() types.VolumesSnapshotStatus {
		st, err := pub.Get("s1")
		assert.NoError(t, err)
		return st.(types.VolumesSnapshotStatus)
	}

	handleVolumesSnapshotConfigImpl(ctx, config)
	first := published()
	assert.False(t, first.HasError())

	handleVolumesSnapshotConfigImpl(ctx, config)
	second := published()
	assert.False(t, second.HasError())
	assert.NotEqual(t, first.RefCount, second.RefCount)
}

// A snapshot volumemgr has no record of cannot be rolled back to, however
// often it is tried. The error answer of the first attempt must not pass for
// a snapshot without volumes on the second.
func TestRollbackToUnknownSnapshotKeepsFailing(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumesSnapshotStatus{},
	})
	assert.NoError(t, err)
	ctx := &volumemgrContext{pubVolumesSnapStatus: pub}

	app := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	const unknown = "no-such-snapshot-for-the-rollback-test"
	config := types.VolumesSnapshotConfig{
		SnapshotID: unknown,
		AppUUID:    app,
		Action:     types.VolumesSnapshotRollback,
	}
	published := func() types.VolumesSnapshotStatus {
		st, err := pub.Get(unknown)
		assert.NoError(t, err)
		return st.(types.VolumesSnapshotStatus)
	}

	handleVolumesSnapshotConfigImpl(ctx, config)
	first := published()
	assert.True(t, first.HasError())
	assert.Equal(t, app, first.AppUUID)

	handleVolumesSnapshotConfigImpl(ctx, config)
	second := published()
	assert.True(t, second.HasError())
	assert.Equal(t, app, second.AppUUID)
	assert.NotEqual(t, first.RefCount, second.RefCount)
}

// A snapshot whose creation failed stays failed when it is asked for again.
// Reporting it as existing would make it available for a rollback.
func TestFailedSnapshotIsNotReportedAsExisting(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumesSnapshotStatus{},
	})
	assert.NoError(t, err)
	ctx := &volumemgrContext{pubVolumesSnapStatus: pub}

	failed := types.VolumesSnapshotStatus{
		SnapshotID:         "s1",
		VolumeSnapshotMeta: map[string]interface{}{},
		ResultOfAction:     types.VolumesSnapshotCreate,
	}
	failed.SetErrorWithSourceAndDescription(
		types.ErrorDescription{Error: "qemu-img failed"}, types.VolumesSnapshotStatus{})
	publishVolumesSnapshotStatus(ctx, &failed)

	answer := createSnapshot(ctx, &types.VolumesSnapshotConfig{
		SnapshotID: "s1",
		Action:     types.VolumesSnapshotCreate,
	})
	assert.True(t, answer.HasError())
	assert.NotEqual(t, types.ErrorSeverityWarning, answer.ErrorSeverity)
	assert.Equal(t, "qemu-img failed", answer.Error)
}
