// Copyright (c) 2025-2026 Zededa, Inc.
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

// appStatus is a minimal AppInstanceStatus fixture: a UUID and a SwState are all
// highPriorityAppsPending / countRunningAppsForUUIDs look at.
type appStatus struct {
	uuid  string
	state types.SwState
}

// newPendingTestContext builds a zedmanagerContext whose subAppInstanceStatus is
// backed by an in-process memory driver populated with the given statuses.
func newPendingTestContext(t *testing.T, statuses []appStatus, delayBaseTime time.Time) *zedmanagerContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceStatus{},
	})
	assert.NoError(t, err)
	for _, s := range statuses {
		u, err := uuid.FromString(s.uuid)
		assert.NoError(t, err)
		status := types.AppInstanceStatus{
			UUIDandVersion: types.UUIDandVersion{UUID: u, Version: "1"},
			State:          s.state,
		}
		assert.NoError(t, pub.Publish(status.Key(), status))
	}

	// Persistent makes Activate populate the subscription from the shared store
	// synchronously, so GetAll reflects the published statuses without pumping
	// the change channel.
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:  agentName,
		TopicImpl:  types.AppInstanceStatus{},
		Persistent: true,
	})
	assert.NoError(t, err)
	assert.NoError(t, sub.Activate())

	return &zedmanagerContext{
		subAppInstanceStatus: sub,
		delayBaseTime:        delayBaseTime,
	}
}

func activeSet(uuids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(uuids))
	for _, u := range uuids {
		m[u] = struct{}{}
	}
	return m
}

const (
	appA = "6ba7b810-9dad-11d1-80b4-00c04fd430a1"
	appB = "6ba7b810-9dad-11d1-80b4-00c04fd430a2"
)

// TestHighPriorityAppsPending checks when low-priority apps are held back.
// The decisive property for a failed high-priority app is that error/terminal
// states (e.g. BROKEN) do not count as running, so a high-priority app that
// never reaches RUNNING keeps low-priority apps waiting only until the startup
// window expires — after which they are released regardless.
func TestHighPriorityAppsPending(t *testing.T) {
	// A delayBaseTime of now leaves the startup window open; a time older than
	// the timeout has it already expired.
	windowOpen := time.Now()
	windowExpired := time.Now().Add(-2 * waitForAppsToStartTimeout)

	tests := []struct {
		name          string
		statuses      []appStatus
		active        map[string]struct{}
		delayBaseTime time.Time
		wantPending   bool
	}{
		{
			name:          "no high-priority apps",
			statuses:      []appStatus{{appA, types.RUNNING}},
			active:        activeSet(),
			delayBaseTime: windowOpen,
			wantPending:   false,
		},
		{
			name:          "all high-priority apps running",
			statuses:      []appStatus{{appA, types.RUNNING}, {appB, types.BOOTING}},
			active:        activeSet(appA, appB),
			delayBaseTime: windowOpen,
			wantPending:   false,
		},
		{
			name:          "one high-priority app not yet started",
			statuses:      []appStatus{{appA, types.RUNNING}, {appB, types.INSTALLED}},
			active:        activeSet(appA, appB),
			delayBaseTime: windowOpen,
			wantPending:   true,
		},
		{
			name:          "window expired releases despite pending app",
			statuses:      []appStatus{{appA, types.RUNNING}, {appB, types.INSTALLED}},
			active:        activeSet(appA, appB),
			delayBaseTime: windowExpired,
			wantPending:   false,
		},
		{
			name:          "failed high-priority app holds until window open",
			statuses:      []appStatus{{appA, types.BROKEN}},
			active:        activeSet(appA),
			delayBaseTime: windowOpen,
			wantPending:   true,
		},
		{
			name:          "failed high-priority app released after window",
			statuses:      []appStatus{{appA, types.BROKEN}},
			active:        activeSet(appA),
			delayBaseTime: windowExpired,
			wantPending:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newPendingTestContext(t, tt.statuses, tt.delayBaseTime)
			assert.Equal(t, tt.wantPending, highPriorityAppsPending(ctx, tt.active))
		})
	}
}
