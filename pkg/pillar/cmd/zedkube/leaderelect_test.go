// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// newTestElection builds an election with the timings a test wants: a short,
// flat re-entry so nothing waits on a real backoff.
func newTestElection(name string) *leaderElection {
	e := &leaderElection{
		name:           name,
		leaseDuration:  60 * time.Second,
		renewDeadline:  45 * time.Second,
		retryPeriod:    10 * time.Second,
		acquireTimeout: time.Second,
		reEntryBase:    time.Second,
		reEntryMax:     time.Second,
		notifyCh:       make(chan struct{}, 1),
	}
	e.eligible.Store(true)
	return e
}

// newElectionTestCtx builds the minimum zedkube that handleControllerStatusChange
// needs: one election, reachable both as statsElection and through elections.
// The package logger is set once by TestMain.
func newElectionTestCtx() *zedkube {
	e := newTestElection(statsLeaseName)
	return &zedkube{statsElection: e, elections: []*leaderElection{e}}
}

// notified reports whether a notification is pending, draining it so the next
// assertion starts clean.
func notified(e *leaderElection) bool {
	select {
	case <-e.notifyCh:
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
		if !z.statsElection.shouldRun.Load() {
			t.Errorf("%v: shouldRun not set", status)
		}
		if !notified(z.statsElection) {
			t.Errorf("%v: handler was not notified", status)
		}
	}
}

// A repeated status is not a transition. zedagent publishes ZedAgentStatus for
// many reasons and arms ConfigGetFail before every request, so acting on every
// publish would stop the election on an unrelated field's change.
func TestControllerStatusIgnoresRepeats(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	if !notified(z.statsElection) {
		t.Fatal("first status did not notify")
	}
	z.feedStatus(types.ConfigGetSuccess)
	if notified(z.statsElection) {
		t.Error("repeated status notified the handler")
	}
}

// A fall to ConfigGetFail is debounced: the election keeps running until the
// controller has stayed unreachable, so one failed poll cannot stop it.
func TestControllerStatusFailIsDebounced(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	notified(z.statsElection)

	z.feedStatus(types.ConfigGetFail)
	if !z.statsElection.shouldRun.Load() {
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
	if !z.statsElection.shouldRun.Load() {
		t.Error("shouldRun cleared despite recovery")
	}
}

// Once the window really elapses, every election stops.
func TestControllerStatusStopFiresAfterDebounce(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	notified(z.statsElection)

	z.scheduleElectionStopAfter(time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for z.statsElection.shouldRun.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if z.statsElection.shouldRun.Load() {
		t.Fatal("election still running after the debounce elapsed")
	}
	if !notified(z.statsElection) {
		t.Error("stop did not notify the handler")
	}
}

// ConfigGetTemporaryFail is set only while an image update is in progress.
// Giving up the lease during a baseos update is not what it asks for.
func TestControllerStatusTemporaryFailKeepsElection(t *testing.T) {
	z := newElectionTestCtx()
	z.feedStatus(types.ConfigGetSuccess)
	notified(z.statsElection)

	z.feedStatus(types.ConfigGetTemporaryFail)
	if !z.statsElection.shouldRun.Load() {
		t.Error("election stopped on a temporary failure")
	}
	if z.electionStopTimer != nil {
		t.Error("a temporary failure scheduled a stop")
	}
}

// Contending needs both flags. Neither alone is enough, which is what keeps a
// node that has not decided its eligibility out of the election.
func TestElectionContendGate(t *testing.T) {
	for _, tc := range []struct {
		shouldRun, eligible, want bool
	}{
		{false, false, false},
		{false, true, false},
		{true, false, false},
		{true, true, true},
	} {
		e := newTestElection("gate-test")
		e.shouldRun.Store(tc.shouldRun)
		e.eligible.Store(tc.eligible)
		if got := e.contend(); got != tc.want {
			t.Errorf("shouldRun=%v eligible=%v: contend()=%v, want %v",
				tc.shouldRun, tc.eligible, got, tc.want)
		}
	}
}

// A flat re-entry (base == max) keeps returning the same delay, which is what
// preserves the stats election's long-standing behavior.
func TestElectionReEntryFlat(t *testing.T) {
	e := newTestElection("flat")
	e.reEntryBase = retryDelay
	e.reEntryMax = retryDelay
	for i := 0; i < 3; i++ {
		if got := e.nextReEntry(); got != retryDelay {
			t.Fatalf("attempt %d: got %v, want %v", i, got, retryDelay)
		}
	}
}

// A bounded backoff doubles up to its ceiling, and leading resets it.
func TestElectionReEntryBackoff(t *testing.T) {
	e := newTestElection("backoff")
	e.reEntryBase = 10 * time.Second
	e.reEntryMax = 60 * time.Second
	e.reEntry.Store(0)

	for _, want := range []time.Duration{
		10 * time.Second, 20 * time.Second, 40 * time.Second,
		60 * time.Second, 60 * time.Second,
	} {
		if got := e.nextReEntry(); got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	e.resetReEntry()
	if got := e.nextReEntry(); got != 10*time.Second {
		t.Errorf("after reset: got %v, want 10s", got)
	}
}

// The lease name is pinned. A hand-typed copy elsewhere would drift from it
// silently, and the stats lease has three independent consumers.
func TestStatsLeaseNamePinned(t *testing.T) {
	if statsLeaseName != "eve-kube-stats-leader" {
		t.Errorf("stats lease name changed to %q", statsLeaseName)
	}
}

// publishLeaderElectionChange must not republish when nothing moved. pubsub
// drops an unchanged item, so stamping LatestChange every call is what made
// this topic churn -- and zedmanager re-drives app instances on that topic.
func TestPublishLeaderElectionChangeDedupes(t *testing.T) {
	logger := logrus.StandardLogger()
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.KubeLeaderElectInfo{},
	})
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}

	z := newElectionTestCtx()
	z.pubLeaderElectInfo = pub

	z.statsElection.isLeader.Store(true)
	z.publishLeaderElectionChange()
	first, err := pub.Get("global")
	if err != nil {
		t.Fatalf("nothing published: %v", err)
	}
	firstInfo := first.(types.KubeLeaderElectInfo)
	if !firstInfo.IsStatsLeader {
		t.Error("published info does not reflect leadership")
	}

	// Same state again: LatestChange must not move.
	z.publishLeaderElectionChange()
	again, _ := pub.Get("global")
	if got := again.(types.KubeLeaderElectInfo); got.LatestChange != firstInfo.LatestChange {
		t.Errorf("republished with no state change: %v -> %v",
			firstInfo.LatestChange, got.LatestChange)
	}

	// A real change publishes again.
	z.statsElection.isLeader.Store(false)
	z.publishLeaderElectionChange()
	third, _ := pub.Get("global")
	if got := third.(types.KubeLeaderElectInfo); got.IsStatsLeader {
		t.Error("state change was not published")
	}
}
