// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// newStartDelayTestContext builds the minimal context the start delay
// computation needs: no base time yet and a stopped fallback timer.
func newStartDelayTestContext(t *testing.T) *zedmanagerContext {
	t.Helper()
	log = base.NewSourceLogObject(logrus.StandardLogger(), agentName, 0)

	timer := time.NewTimer(waitForAppsToStartTimeout)
	if !timer.Stop() {
		<-timer.C
	}
	return &zedmanagerContext{priorityStartTimer: timer}
}

// TestAppStartTimeConfigBeforeZedAgentStatus covers the ordering where an
// AppInstanceConfig is handled before the ZedAgentStatus that reports a
// successful config get. The start moment must still be a real one, otherwise
// the delay is added to the zero time and the app is never held back.
func TestAppStartTimeConfigBeforeZedAgentStatus(t *testing.T) {
	ctx := newStartDelayTestContext(t)
	const delay = 3 * time.Minute
	config := types.AppInstanceConfig{Delay: delay}

	before := time.Now()
	first := appStartTime(ctx, config)
	after := time.Now()

	assert.False(t, first.IsZero())
	assert.False(t, first.Before(before.Add(delay)))
	assert.False(t, first.After(after.Add(delay)))
	// The whole point of the delay: the app is not allowed to start yet.
	assert.True(t, time.Now().Before(first))

	// The status that normally establishes the base time arrives afterwards. It
	// must not move the start moment of an app created before it, so that the
	// two orderings are indistinguishable.
	handleZedAgentStatusImpl(ctx, "zedagent",
		types.ZedAgentStatus{ConfigGetStatus: types.ConfigGetSuccess})
	assert.Equal(t, first, appStartTime(ctx, config))

	// An app without a delay is not held back.
	assert.False(t, time.Now().Before(appStartTime(ctx, types.AppInstanceConfig{})))

	// Establishing the base time must arm the fallback that releases
	// low-priority apps; Stop reports true only for a timer that is running.
	assert.True(t, ctx.priorityStartTimer.Stop())
}

// TestAppStartTimeZedAgentStatusFirst is the ordering that used to work: the
// base time is known before any app config arrives.
func TestAppStartTimeZedAgentStatusFirst(t *testing.T) {
	ctx := newStartDelayTestContext(t)
	const delay = 3 * time.Minute

	handleZedAgentStatusImpl(ctx, "zedagent",
		types.ZedAgentStatus{ConfigGetStatus: types.ConfigGetSuccess})
	baseTime := ctx.delayBaseTime
	assert.False(t, baseTime.IsZero())

	assert.Equal(t, baseTime.Add(delay),
		appStartTime(ctx, types.AppInstanceConfig{Delay: delay}))
	// A later app config must not re-base the delay.
	assert.Equal(t, baseTime, ctx.delayBaseTime)
}
