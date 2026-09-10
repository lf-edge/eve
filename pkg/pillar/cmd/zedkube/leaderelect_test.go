// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// newElectionTestCtx builds the minimum zedkube needed by
// handleControllerStatusChange: the desired-state atomic and the notify
// channel. The package logger is set once by TestMain.
func newElectionTestCtx() *zedkube {
	return &zedkube{electionNotifyCh: make(chan struct{}, 1)}
}

// notified reports whether a notification is pending, draining it so the
// next assertion starts clean.
func notified(z *zedkube) bool {
	select {
	case <-z.electionNotifyCh:
		return true
	default:
		return false
	}
}

func (z *zedkube) feedStatus(s types.ConfigGetStatus) {
	z.handleControllerStatusChange(&types.ZedAgentStatus{ConfigGetStatus: s})
}

func TestControllerStatusRisingEdgeStartsElection(t *testing.T) {
	for _, status := range []types.ConfigGetStatus{
		types.ConfigGetSuccess, types.ConfigGetReadSaved,
	} {
		z := newElectionTestCtx()
		z.feedStatus(status)
		if !z.electionShouldRun.Load() {
			t.Errorf("%v: electionShouldRun not set", status)
		}
		if !notified(z) {
			t.Errorf("%v: handler was not notified", status)
		}
	}
}

// A repeated status is not a transition. zedagent publishes ZedAgentStatus
// for many reasons and arms ConfigGetFail before every request, so acting on
// every publish would stop the election on an unrelated field's change.
func TestControllerStatusIgnoresRepeats(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	if !notified(z) {
		t.Fatal("first status did not notify")
	}
	z.feedStatus(types.ConfigGetSuccess)
	if notified(z) {
		t.Error("repeated status notified the handler")
	}
}

// A fall to ConfigGetFail is debounced: the election keeps running until the
// controller has stayed unreachable, so one failed poll cannot stop it.
func TestControllerStatusFailIsDebounced(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	notified(z)

	z.feedStatus(types.ConfigGetFail)
	if !z.electionShouldRun.Load() {
		t.Error("election stopped immediately on ConfigGetFail")
	}
	if z.electionStopTimer == nil {
		t.Error("no debounced stop was scheduled")
	}
}

// Recovering inside the debounce window cancels the pending stop.
func TestControllerStatusRecoveryCancelsStop(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	z.feedStatus(types.ConfigGetFail)
	if z.electionStopTimer == nil {
		t.Fatal("no debounced stop was scheduled")
	}
	z.feedStatus(types.ConfigGetSuccess)
	if z.electionStopTimer != nil {
		t.Error("pending stop survived recovery")
	}
	if !z.electionShouldRun.Load() {
		t.Error("electionShouldRun cleared despite recovery")
	}
}

// Once the window really elapses, the election stops.
func TestControllerStatusStopFiresAfterDebounce(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	notified(z)

	z.scheduleElectionStopAfter(time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for z.electionShouldRun.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if z.electionShouldRun.Load() {
		t.Fatal("election still running after the debounce elapsed")
	}
	if !notified(z) {
		t.Error("stop did not notify the handler")
	}
}

// ConfigGetTemporaryFail is set only while an image update is in progress.
// Giving up the lease during a baseos update is not what it asks for.
func TestControllerStatusTemporaryFailKeepsElection(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	notified(z)

	z.feedStatus(types.ConfigGetTemporaryFail)
	if !z.electionShouldRun.Load() {
		t.Error("election stopped on a temporary failure")
	}
	if z.electionStopTimer != nil {
		t.Error("a temporary failure scheduled a stop")
	}
}
