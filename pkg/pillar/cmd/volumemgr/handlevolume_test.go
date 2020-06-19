// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

// Interface to worker to run the create and destroy in separate goroutines

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func TestIsErrorSourceOnPubSub(t *testing.T) {
	status := &types.VolumeStatus{}
	errStr := "test1"
	status.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
	log.Infof("set error %s", status.Error)
	ctx := initStatusCtx(t)
	publishVolumeStatus(&ctx, status)
	status = lookupVolumeStatus(&ctx, status.Key())
	assert.True(t, status.HasError())
	assert.True(t, status.IsErrorSource(types.ContentTreeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.False(t, status.IsErrorSource(types.VolumeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.Equal(t, errStr, status.Error)
	status.ClearErrorWithSource()
	log.Infof("cleared error %s", status.Error)
	assert.False(t, status.IsErrorSource(types.ContentTreeStatus{}),
		"Pubsub error source type: %T", status.ErrorSourceType)
	assert.Equal(t, "", status.Error)
}

func initStatusCtx(t *testing.T) volumemgrContext {
	ctx := volumemgrContext{}
	ps := pubsub.New(&pubsub.EmptyDriver{})

	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		AgentScope: types.AppImgObj,
		TopicType:  types.VolumeStatus{},
	})
	assert.Nil(t, err)
	ctx.pubVolumeStatus = pubVolumeStatus
	return ctx
}
