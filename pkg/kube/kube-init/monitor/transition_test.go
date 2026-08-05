// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

func TestParseTransitionMarker(t *testing.T) {
	now := time.Now().Unix()

	cases := []struct {
		name    string
		content string
		wantTS  int64
		wantCnt int
		wantErr bool
	}{
		{
			name:    "valid recent",
			content: fmt.Sprintf("%d 2", now-30),
			wantTS:  now - 30,
			wantCnt: 2,
		},
		{
			name:    "single field rejected",
			content: fmt.Sprintf("%d", now),
			wantErr: true,
		},
		{
			name:    "empty file rejected",
			content: "",
			wantErr: true,
		},
		{
			name:    "non-numeric timestamp rejected",
			content: "notanumber 1",
			wantErr: true,
		},
		{
			name:    "non-numeric count rejected",
			content: fmt.Sprintf("%d bogus", now),
			wantErr: true,
		},
		{
			name:    "zero timestamp rejected",
			content: "0 1",
			wantErr: true,
		},
		{
			name:    "negative timestamp rejected",
			content: "-5 1",
			wantErr: true,
		},
		{
			name:    "more than 60s in the future rejected",
			content: fmt.Sprintf("%d 1", now+120),
			wantErr: true,
		},
		{
			name:    "60s tolerance accepted",
			content: fmt.Sprintf("%d 1", now+30),
			wantTS:  now + 30,
			wantCnt: 1,
		},
		{
			name:    "trailing whitespace tolerated",
			content: fmt.Sprintf("  %d   3  ", now-10),
			wantTS:  now - 10,
			wantCnt: 3,
		},
		{
			name:    "extra fields tolerated (first two win)",
			content: fmt.Sprintf("%d 1 extra-junk", now-5),
			wantTS:  now - 5,
			wantCnt: 1,
		},
	}

	dir := t.TempDir()
	tmp := dir + "/marker"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(tmp, []byte(c.content), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ts, cnt, err := parseTransitionMarker(tmp)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if ts != c.wantTS {
				t.Errorf("ts = %d, want %d", ts, c.wantTS)
			}
			if cnt != c.wantCnt {
				t.Errorf("cnt = %d, want %d", cnt, c.wantCnt)
			}
		})
	}

	// missing file → distinct error surface (os.ReadFile fails before
	// any field parsing runs).
	if _, _, err := parseTransitionMarker(dir + "/does-not-exist"); err == nil {
		t.Errorf("missing file: expected error, got nil")
	}
}

// TestStartJoinWatchdogWithoutMarker checks the watchdog stays dormant
// when no join is in flight: no marker, no goroutine, and the
// double-start guard left clear so a later real join can start one.
func TestStartJoinWatchdogWithoutMarker(t *testing.T) {
	if _, err := os.Stat(string(state.TransitionToCluster)); !os.IsNotExist(err) {
		t.Skipf("host has a real %s marker", state.TransitionToCluster)
	}

	StartJoinWatchdog(context.Background())

	if joinWatchdogActive.Load() {
		t.Error("watchdog marked active with no transition marker on disk")
	}
}

// TestSinceJoinProgressFallsBackToMarker: with no advance recorded yet
// this boot (daemon restarted mid-join), the stall clock has to run
// from the marker's own timestamp rather than reading as "no time has
// passed", which would make the watchdog unable to ever fire.
func TestSinceJoinProgressFallsBackToMarker(t *testing.T) {
	resetJoinProgress(t)
	written := time.Now().Add(-90 * time.Second)
	if got := sinceJoinProgress(written); got < 80*time.Second {
		t.Errorf("sinceJoinProgress = %v with no recorded progress, want ~90s from the marker", got)
	}
}

// TestNoteJoinProgressKicksTheClock is the property that stops a slow
// join being rebooted: any advance restarts the stall window, however
// long the join has already been running.
func TestNoteJoinProgressKicksTheClock(t *testing.T) {
	resetJoinProgress(t)
	// Progress is only recorded while a join is actually being
	// watched, so stand in for the running watchdog.
	joinWatchdogActive.Store(true)
	t.Cleanup(func() { joinWatchdogActive.Store(false) })
	written := time.Now().Add(-30 * time.Minute)

	NoteJoinProgress("WAIT_K3S_READY")

	got := sinceJoinProgress(written)
	if got > time.Second {
		t.Errorf("sinceJoinProgress = %v after progress, want ~0 — a join that is "+
			"still advancing must never trip the stall limit", got)
	}
	if got >= joinStallTimeout {
		t.Errorf("a just-advanced join would be rebooted (%v >= %v)", got, joinStallTimeout)
	}
}

// TestMarkJoinCompleteIsSafeWithoutAMarker — the FSM calls this on every
// arrival at RUNNING, including boots where no join is in flight.
func TestMarkJoinCompleteIsSafeWithoutAMarker(t *testing.T) {
	resetJoinProgress(t)
	if _, err := os.Stat(string(state.TransitionToCluster)); !os.IsNotExist(err) {
		t.Skipf("host has a real %s marker", state.TransitionToCluster)
	}
	MarkJoinComplete() // must not panic or create anything
	if _, err := os.Stat(string(state.TransitionToCluster)); !os.IsNotExist(err) {
		t.Error("MarkJoinComplete created a transition marker")
	}
}

func resetJoinProgress(t *testing.T) {
	t.Helper()
	joinProgress.mu.Lock()
	joinProgress.at = time.Time{}
	joinProgress.mu.Unlock()
	t.Cleanup(func() {
		joinProgress.mu.Lock()
		joinProgress.at = time.Time{}
		joinProgress.mu.Unlock()
	})
}

// TestNoteJoinProgressIgnoredWithoutWatchdog: first-boot deploy and
// steady-state readiness checks call the same hook. With no join in
// flight they must not stamp the clock — otherwise a later join
// inherits a timestamp from an unrelated episode and starts with part
// of its stall budget already spent, which is how edge-dev2 got
// rebooted while perfectly healthy.
func TestNoteJoinProgressIgnoredWithoutWatchdog(t *testing.T) {
	resetJoinProgress(t)
	if joinWatchdogActive.Load() {
		t.Fatal("precondition: no watchdog should be active")
	}

	NoteJoinProgress("system pods 3/5 ready")

	joinProgress.mu.Lock()
	at := joinProgress.at
	joinProgress.mu.Unlock()
	if !at.IsZero() {
		t.Errorf("progress recorded with no join in flight (at = %v)", at)
	}
}
