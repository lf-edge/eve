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

func TestSyncRuntimeErr(t *testing.T) {
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	zedrouterPub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedrouter",
		TopicType: types.AppRuntimeStatus{},
	})
	assert.NoError(t, err)
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedrouter",
		MyAgentName: agentName,
		TopicImpl:   types.AppRuntimeStatus{},
	})
	assert.NoError(t, err)
	assert.NoError(t, sub.Activate())
	ctx := &zedmanagerContext{subAppRuntimeStatus: sub}

	appUUID := uuid.Must(uuid.FromString("11111111-1111-1111-1111-111111111111"))
	status := &types.AppInstanceStatus{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID},
	}
	status.SetErrorWithSource("lifecycle error", types.AppInstanceStatus{}, time.Now())
	// A non-persistent subscription sees a change only once it is processed.
	publish := func(desc types.ErrorDescription) {
		rs := types.AppRuntimeStatus{UUID: appUUID.String()}
		rs.SetErrorDescription(desc)
		assert.NoError(t, zedrouterPub.Publish(rs.Key(), rs))
		sub.ProcessChange(<-sub.MsgChan())
	}
	errTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	assert.False(t, syncRuntimeErr(ctx, status), "nothing published")

	publish(types.ErrorDescription{Error: "cloud-init failed", ErrorTime: errTime,
		ErrorSeverity: types.ErrorSeverityWarning})
	assert.True(t, syncRuntimeErr(ctx, status))
	assert.Equal(t, "cloud-init failed", status.RuntimeErr.Error)
	assert.Equal(t, types.ErrorSeverityWarning, status.RuntimeErr.ErrorSeverity)
	assert.Equal(t, "lifecycle error", status.Error, "lifecycle error is kept")

	assert.False(t, syncRuntimeErr(ctx, status), "unchanged")

	publish(types.ErrorDescription{Error: "cloud-init failed", ErrorTime: errTime.Add(time.Minute),
		ErrorSeverity: types.ErrorSeverityWarning})
	assert.True(t, syncRuntimeErr(ctx, status), "newer occurrence")

	assert.NoError(t, zedrouterPub.Unpublish(appUUID.String()))
	sub.ProcessChange(<-sub.MsgChan())
	assert.True(t, syncRuntimeErr(ctx, status))
	assert.Empty(t, status.RuntimeErr.Error)
	assert.Equal(t, "lifecycle error", status.Error)
}
