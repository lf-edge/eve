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

// This test is deliberately written against countRunningAppsForUUIDs and the
// startup-timeout condition only, so the same source compiles and runs on both
// the unmodified master tree and this change. It documents that a high-priority
// app that fails to boot does not count as running, and that low-priority apps
// are therefore released by the startup timeout rather than blocked forever.

const failedHighPriApp = "6ba7b810-9dad-11d1-80b4-00c04fd430f1"

// newBootPriorityContext builds a zedmanagerContext whose subAppInstanceStatus
// is a memory-backed subscription populated with the given app states.
func newBootPriorityContext(t *testing.T, states map[string]types.SwState, delayBaseTime time.Time) *zedmanagerContext {
	t.Helper()
	logger := logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.AppInstanceStatus{},
	})
	assert.NoError(t, err)
	for u, state := range states {
		id, err := uuid.FromString(u)
		assert.NoError(t, err)
		status := types.AppInstanceStatus{
			UUIDandVersion: types.UUIDandVersion{UUID: id, Version: "1"},
			State:          state,
		}
		assert.NoError(t, pub.Publish(status.Key(), status))
	}
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

// releaseLowPriority mirrors the low-priority release condition: release once
// all high-priority apps are running, or the startup window has expired. On
// master this is the condition inside checkLowPriorityApps; on this change the
// equivalent is !highPriorityAppsPending.
func releaseLowPriority(ctx *zedmanagerContext, active map[string]struct{}) bool {
	running := countRunningAppsForUUIDs(ctx, active)
	return running >= uint(len(active)) ||
		time.Now().After(ctx.delayBaseTime.Add(waitForAppsToStartTimeout))
}

// TestFailedHighPriorityAppDoesNotBlockForever models an app that was active
// before the reboot (high priority) and had an app-direct adapter, eth2, which
// is gone after the reboot. DomainStatus for it never reaches a running state,
// so it stays in a failed/non-running state. Low-priority apps must not be held
// forever: the startup timeout releases them.
func TestFailedHighPriorityAppDoesNotBlockForever(t *testing.T) {
	active := map[string]struct{}{failedHighPriApp: {}}

	// A failed high-priority app can settle in different non-running states
	// depending on where boot failed (device model died -> BROKEN; never got
	// far enough to boot because the adapter is missing -> INSTALLED).
	for _, failState := range []types.SwState{types.BROKEN, types.INSTALLED} {
		t.Run(failState.String(), func(t *testing.T) {
			// Startup window still open: the app is not running and the timeout
			// has not passed, so low-priority apps stay held.
			ctxOpen := newBootPriorityContext(t,
				map[string]types.SwState{failedHighPriApp: failState}, time.Now())
			assert.Equal(t, uint(0), countRunningAppsForUUIDs(ctxOpen, active),
				"a failed high-priority app must not count as running")
			assert.False(t, releaseLowPriority(ctxOpen, active),
				"low-priority apps stay held while the startup window is open")

			// Startup window expired: low-priority apps are released even though
			// the high-priority app never started - i.e. not blocked forever.
			ctxExpired := newBootPriorityContext(t,
				map[string]types.SwState{failedHighPriApp: failState},
				time.Now().Add(-2*waitForAppsToStartTimeout))
			assert.True(t, releaseLowPriority(ctxExpired, active),
				"low-priority apps are released once the startup window expires")
		})
	}
}
