// Copyright (c) 2026, Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"testing"
	"time"
)

func TestPauseLimitTimer(t *testing.T) {
	th := &TestHarness{}
	ch, stop := th.pauseLimitTimer()
	defer stop()
	if ch != nil {
		t.Fatal("no limit configured, but the timer channel is not nil")
	}

	th.pauseLimit = 10 * time.Millisecond
	ch, stop = th.pauseLimitTimer()
	defer stop()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("pause limit timer did not fire")
	}
}

func TestReleasePause(t *testing.T) {
	th := &TestHarness{
		resume:             make(chan struct{}),
		pausedOnFailure:    "boom",
		pausedAtCheckpoint: "cp",
		pauseAtCheckpoint:  "cp",
	}
	paused := th.resume

	th.releasePause(paused)
	select {
	case <-paused:
	default:
		t.Fatal("waiters of the pause were not released")
	}
	if th.pausedOnFailure != "" || th.pausedAtCheckpoint != "" || th.pauseAtCheckpoint != "" {
		t.Fatalf("pause state not cleared: %q %q %q",
			th.pausedOnFailure, th.pausedAtCheckpoint, th.pauseAtCheckpoint)
	}

	// A stale limit expiry must not release a later pause.
	later := th.resume
	th.pausedOnFailure = "again"
	th.releasePause(paused)
	select {
	case <-later:
		t.Fatal("a stale pause limit released a newer pause")
	default:
	}
	if th.pausedOnFailure != "again" {
		t.Fatal("a stale pause limit cleared the newer pause state")
	}
}
