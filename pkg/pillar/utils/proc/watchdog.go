// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// WatchdogKicker is used in some proc functions that have a timeout,
// to tell the watchdog agent is still alive.
type WatchdogKicker struct {
	ps        *pubsub.PubSub
	agentName string
	warnTime  time.Duration
	errTime   time.Duration
}

// NewWatchdogKicker creates a new WatchdogKick.
func NewWatchdogKicker(ps *pubsub.PubSub, agentName string,
	warnTime time.Duration, errTime time.Duration) *WatchdogKicker {
	return &WatchdogKicker{
		ps:        ps,
		agentName: agentName,
		warnTime:  warnTime,
		errTime:   errTime,
	}
}

// Kick tells the watchdog that agent is still alive.
func (wk *WatchdogKicker) Kick() {
	if wk == nil {
		return
	}
	wk.ps.StillRunning(wk.agentName, wk.warnTime, wk.errTime)
}
