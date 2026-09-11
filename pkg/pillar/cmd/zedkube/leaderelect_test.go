// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
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

// newElectionTestCtx builds the minimum zedkube the election code needs: both
// elections, reachable individually and through the elections slice. The
// package logger is set once by TestMain.
func newElectionTestCtx() *zedkube {
	stats := newTestElection(statsLeaseName)
	appOp := newTestElection(appOpLeaseName)
	// eve-app-op eligibility is decided, not assumed.
	appOp.eligible.Store(false)
	return &zedkube{
		statsElection: stats,
		appOpElection: appOp,
		elections:     []*leaderElection{stats, appOp},
	}
}

// newElectionTestCtxWithPub is newElectionTestCtx plus a real
// KubeLeaderElectInfo publication, for the assertions that read back what was
// published.
func newElectionTestCtxWithPub(t *testing.T) (*zedkube, pubsub.Publication) {
	t.Helper()
	ps := pubsub.New(&pubsub.EmptyDriver{}, logrus.StandardLogger(), log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.KubeLeaderElectInfo{},
	})
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	z := newElectionTestCtx()
	z.pubLeaderElectInfo = pub
	return z, pub
}

// testUUID is a fresh UUID, failing the test rather than the caller if the
// generator errors.
func testUUID(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("uuid.NewV4: %v", err)
	}
	return u
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

// An unknown node UUID must read as ineligible. IsTieBreakerNode reports false
// for an empty UUID, which reads as "not the tie-breaker", so deciding
// eligibility before the UUID is known would let a tie-breaker contend -- the
// ordering that matters, because the first EdgeNodeClusterConfig is processed
// before zedkube learns its own UUID.
func TestAppOpEligibilityWaitsForNodeUUID(t *testing.T) {
	tieBreaker := testUUID(t)
	z := newElectionTestCtx()
	z.clusterConfig = types.EdgeNodeClusterConfig{
		TieBreakerNodeID: types.UUIDandVersion{UUID: tieBreaker},
	}

	// UUID not yet known: must not contend, even though the config is here.
	z.updateAppOpEligibility()
	if z.appOpElection.eligible.Load() {
		t.Error("eligible with an unknown node UUID")
	}

	// This node turns out to be the tie-breaker: still ineligible.
	z.nodeuuid = tieBreaker.String()
	z.updateAppOpEligibility()
	if z.appOpElection.eligible.Load() {
		t.Error("the tie-breaker was made eligible")
	}

	// A worker node is eligible.
	z.nodeuuid = testUUID(t).String()
	z.updateAppOpEligibility()
	if !z.appOpElection.eligible.Load() {
		t.Error("a worker node was not made eligible")
	}
}

// Eligibility is re-decided, not latched: a node that becomes the tie-breaker
// gives the lease up, and one that stops being it starts to contend.
func TestAppOpEligibilityFollowsTieBreakerMoves(t *testing.T) {
	self := testUUID(t)
	other := testUUID(t)
	z := newElectionTestCtx()
	z.nodeuuid = self.String()

	z.clusterConfig = types.EdgeNodeClusterConfig{
		TieBreakerNodeID: types.UUIDandVersion{UUID: other},
	}
	z.updateAppOpEligibility()
	if !z.appOpElection.eligible.Load() {
		t.Fatal("not eligible while another node is the tie-breaker")
	}

	z.clusterConfig.TieBreakerNodeID = types.UUIDandVersion{UUID: self}
	z.updateAppOpEligibility()
	if z.appOpElection.eligible.Load() {
		t.Error("still eligible after becoming the tie-breaker")
	}

	z.clusterConfig.TieBreakerNodeID = types.UUIDandVersion{UUID: other}
	z.updateAppOpEligibility()
	if !z.appOpElection.eligible.Load() {
		t.Error("did not resume contending after ceasing to be the tie-breaker")
	}
}

// The two elections publish independently: holding one says nothing about the
// other.
func TestPublishReportsBothElections(t *testing.T) {
	z, pub := newElectionTestCtxWithPub(t)

	z.appOpElection.isLeader.Store(true)
	z.appOpElection.identity.Store("node-a")
	z.publishLeaderElectionChange()

	item, err := pub.Get("global")
	if err != nil {
		t.Fatalf("nothing published: %v", err)
	}
	info := item.(types.KubeLeaderElectInfo)
	if !info.IsAppOpLeader {
		t.Error("IsAppOpLeader not reported")
	}
	if info.AppOpLeaderIdentity != "node-a" {
		t.Errorf("AppOpLeaderIdentity = %q, want node-a", info.AppOpLeaderIdentity)
	}
	if info.IsStatsLeader {
		t.Error("app-op leadership leaked into IsStatsLeader")
	}
}

// publishLeaderElectionChange must not republish when nothing moved. pubsub
// drops an unchanged item, so stamping LatestChange every call is what made
// this topic churn -- and zedmanager re-drives app instances on that topic.
func TestPublishLeaderElectionChangeDedupes(t *testing.T) {
	z, pub := newElectionTestCtxWithPub(t)

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
