// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func TestIsErrorSourceOnPubSub(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "volumemgr", 0)
	status := &types.VolumeStatus{}
	errStr := "test1"
	status.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
	log.Functionf("set error %s", status.Error)
	ctx := initStatusCtx(t)
	publishVolumeStatus(&ctx, status)
	status = ctx.LookupVolumeStatus(status.Key())
	assert.True(t, status.HasError())
	assert.True(t, status.IsErrorSource(types.ContentTreeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.False(t, status.IsErrorSource(types.VolumeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.Equal(t, errStr, status.Error)
	status.ClearErrorWithSource()
	log.Functionf("cleared error %s", status.Error)
	assert.False(t, status.IsErrorSource(types.ContentTreeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.Equal(t, "", status.Error)
}

func initStatusCtx(t *testing.T) volumemgrContext {
	ctx := volumemgrContext{}
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeStatus{},
	})
	assert.Nil(t, err)
	ctx.pubVolumeStatus = pubVolumeStatus
	return ctx
}

// initVolumeModifyCtx builds on initStatusCtx with the additional
// subscriptions/config handleVolumeModify's call chain (updateVolumeStatusRefCount,
// doUpdateVol, updateVolumeRefStatus) touches, so handleVolumeModify can be
// exercised directly instead of only its pubsub-facing helpers.
func initVolumeModifyCtx(t *testing.T) volumemgrContext {
	ctx := initStatusCtx(t)
	ctx.globalConfig = types.DefaultConfigItemValueMap()
	ctx.volumeConfigCreateDeferredMap = make(map[string]*types.VolumeConfig)

	ps := pubsub.New(&pubsub.EmptyDriver{}, logrus.StandardLogger(), log)

	subVolumeConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeConfig{},
		Ctx:         &ctx,
	})
	assert.Nil(t, err)
	ctx.subVolumeConfig = subVolumeConfig
	subVolumeConfig.Activate()

	subVolumeRefConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.VolumeRefConfig{},
		Ctx:         &ctx,
	})
	assert.Nil(t, err)
	ctx.subVolumeRefConfig = subVolumeRefConfig
	subVolumeRefConfig.Activate()

	return ctx
}

// TestHandleVolumeModifyResyncsIsReplicated is a regression test for a cluster
// (ENC) bug: when a "replace node" operation reassigns a volume's Designated
// Node ID to this node, zedagent republishes VolumeConfig with IsReplicated
// flipped to false, but handleVolumeModify never copied the new value onto
// the already-existing VolumeStatus -- it stayed frozen at whatever value was
// set when the status was first created. Since DestroyVolume() gates PVC
// deletion on VolumeStatus.IsReplicated, a stale "true" meant the
// newly-designated node silently skipped deleting the PVC on Delete.
func TestHandleVolumeModifyResyncsIsReplicated(t *testing.T) {
	ctx := initVolumeModifyCtx(t)

	volumeID := uuid.Must(uuid.NewV4())
	contentID := uuid.Must(uuid.NewV4())

	// Simulate this node's pre-fix state: it was a replica (the volume's PVC
	// lives on a different, designated node), already fully reconciled.
	status := &types.VolumeStatus{
		VolumeID:     volumeID,
		ContentID:    contentID,
		MaxVolSize:   1024,
		State:        types.CREATED_VOLUME,
		SubState:     types.VolumeSubStateCreated,
		IsReplicated: true,
	}
	publishVolumeStatus(&ctx, status)

	// Controller reassigns DNID to this node: same volume, same content,
	// only IsReplicated flips to false.
	config := types.VolumeConfig{
		VolumeID:     volumeID,
		ContentID:    contentID,
		MaxVolSize:   1024,
		IsReplicated: false,
	}

	handleVolumeModify(&ctx, config.Key(), config, types.VolumeConfig{})

	got := ctx.LookupVolumeStatus(config.Key())
	assert.NotNil(t, got)
	assert.False(t, got.IsReplicated,
		"VolumeStatus.IsReplicated must be resynced from VolumeConfig on modify, not frozen at creation time")
}
