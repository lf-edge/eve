// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const retryDelay = 5 * time.Minute

// statsLeaseName is the lease the stats collector, the node-prune sweep and
// isDecisionNode all arbitrate on. Pinned as a constant because a hand-typed
// copy elsewhere would drift from it silently.
const statsLeaseName = "eve-kube-stats-leader"

// appOpLeaseName is the lease that decides the one node allowed to act on an
// app whose designated node is down. Pinned for the same reason.
const appOpLeaseName = "eve-app-op"

// leaderElection is one Kubernetes leader election: its lease, the two flags
// that gate contending for it, and the state its callbacks write. Every field
// that another election would need its own copy of lives here rather than on
// zedkube, so stopping or retrying one election cannot disturb another.
type leaderElection struct {
	// name is the lease name, and labels this election in every log line.
	name string

	// Lease timings. Per-election because they encode how long a handover
	// may take: a stats collector tolerates a slow one, a decision other
	// agents wait on does not.
	leaseDuration time.Duration
	renewDeadline time.Duration
	retryPeriod   time.Duration

	// acquireTimeout bounds how long acquisition may stall before the
	// context is cancelled and the clientset rebuilt, which is how a
	// rotated TLS cert is picked up. reEntryBase and reEntryMax bound the
	// backoff before re-entering the election after it exits; set both to
	// the same value for a flat delay.
	acquireTimeout time.Duration
	reEntryBase    time.Duration
	reEntryMax     time.Duration

	// shouldRun is the desired state, driven by controller reachability.
	// eligible is whether this node may contend at all. Contending needs
	// both. notifyCh wakes the handler to act on their latest values.
	shouldRun atomic.Bool
	eligible  atomic.Bool
	notifyCh  chan struct{}

	// Written from the client-go callbacks and the election goroutine, read
	// by publishLeaderElectionChange and by other agents' code, so all of
	// it is atomic.
	isLeader   atomic.Bool
	running    atomic.Bool
	inElection atomic.Bool
	identity   atomic.Value
	reEntry    atomic.Int64

	// Owned by the handler loop alone.
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// notify wakes the handler to act on the latest shouldRun and eligible.
// Non-blocking: a pending notification already carries the newest values.
func (e *leaderElection) notify() {
	select {
	case e.notifyCh <- struct{}{}:
	default:
	}
}

// contend reports whether this node should be in this election right now.
func (e *leaderElection) contend() bool {
	return e.shouldRun.Load() && e.eligible.Load()
}

// identityString is the observed leader, or "" before one is seen.
func (e *leaderElection) identityString() string {
	if v := e.identity.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// nextReEntry returns the delay to wait before re-entering the election, and
// advances the backoff. Called from both the handler loop and the election
// goroutine, hence the atomic.
func (e *leaderElection) nextReEntry() time.Duration {
	delay := time.Duration(e.reEntry.Load())
	if delay <= 0 {
		delay = e.reEntryBase
	}
	next := delay * 2
	if next > e.reEntryMax {
		next = e.reEntryMax
	}
	e.reEntry.Store(int64(next))
	return delay
}

// resetReEntry returns the backoff to its floor, called once leading starts.
func (e *leaderElection) resetReEntry() {
	e.reEntry.Store(int64(e.reEntryBase))
}

// scheduleReEntry publishes the state change from an election dropping out
// and wakes the handler again after the backoff.
func (z *zedkube) scheduleReEntry(e *leaderElection) time.Duration {
	delay := e.nextReEntry()
	z.publishLeaderElectionChange()
	time.AfterFunc(delay, e.notify)
	return delay
}

// isStatsLeader reports whether this node holds the stats lease. Readers are
// kubestatscollect, prunenodes and isDecisionNode.
func (z *zedkube) isStatsLeader() bool {
	return z.statsElection.isLeader.Load()
}

// updateAppOpEligibility re-decides whether this node may contend for the
// eve-app-op lease. The tie-breaker is excluded: it exists for quorum and
// does not run app workloads.
//
// Both inputs can arrive late, in either order. IsTieBreakerNode reports
// false for an empty UUID, so an unknown node UUID must read as ineligible
// -- not eligible -- or a tie-breaker could contend before its UUID is
// known. A node that cannot decide must not contend, since every app can
// still start through its own designated node with nobody holding the lease.
func (z *zedkube) updateAppOpEligibility() {
	eligible := false
	if z.nodeuuid != "" {
		eligible = !z.clusterConfig.IsTieBreakerNode(z.nodeuuid)
	}
	// Log every decision, not just a change: a wrong first decision that is
	// never revisited is invisible otherwise.
	log.Noticef("updateAppOpEligibility: nodeuuid %q tiebreaker %v -> eligible %v",
		z.nodeuuid, z.clusterConfig.TieBreakerNodeID, eligible)
	z.appOpElection.eligible.Store(eligible)
	z.appOpElection.notify()
}

func (z *zedkube) handleLeaderElection(e *leaderElection) {
	// stopElection cancels the running election goroutine and blocks until
	// it fully exits. After this call all goroutine-owned state
	// (isLeader, identity, running) is cleaned up.
	stopElection := func() {
		if e.cancel != nil {
			log.Noticef("handleLeaderElection(%s): cancelling leader election", e.name)
			e.cancel()
			e.cancel = nil
			e.wg.Wait()
		}
	}

	for {
		log.Noticef("handleLeaderElection(%s): Waiting for signal", e.name)
		<-e.notifyCh

		if !e.contend() {
			// Stop requested — cancel, wait for the goroutine to finish,
			// then update state and publish once with final values.
			stopElection()
			e.inElection.Store(false)
			z.publishLeaderElectionChange()
			log.Noticef("handleLeaderElection(%s): Stopped", e.name)
			continue
		}

		e.inElection.Store(true)

		// If the election goroutine is still running, nothing to do
		if e.running.Load() {
			log.Noticef("handleLeaderElection(%s): Election goroutine still running, skip",
				e.name)
			continue
		}

		// Create a cancelable context and start a timer that cancels it if
		// the lease is neither acquired nor a leader observed in time (e.g.
		// a failing connection caused by stale TLS certificates). The timer
		// is stopped once OnStartedLeading or OnNewLeader is triggered.
		baseCtx, cancel := context.WithCancel(context.Background())
		e.cancel = cancel
		acquireTimeout := time.AfterFunc(e.acquireTimeout, func() {
			log.Noticef("handleLeaderElection(%s): failed to acquire or observe "+
				"lease within %v, cancelling", e.name, e.acquireTimeout)
			// A race between this cancel() and the handler's own is
			// harmless: calling a context's cancel more than once has no
			// effect after the first.
			cancel()
		})

		// Always create a fresh clientset to pick up any kubeconfig
		// changes (e.g. TLS cert regeneration during cluster join)
		clientset, err := getKubeClientSet()
		if err != nil {
			acquireTimeout.Stop()
			cancel()
			e.cancel = nil
			delay := z.scheduleReEntry(e)
			log.Errorf("handleLeaderElection(%s): can't get clientset %v, retry in %v",
				e.name, err, delay)
			continue
		}

		lock := &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      e.name,
				Namespace: kubeapi.EVEKubeNameSpace,
			},
			Client: clientset.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: z.nodeName,
			},
		}

		lec := leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   e.leaseDuration,
			RenewDeadline:   e.renewDeadline,
			RetryPeriod:     e.retryPeriod,
			ReleaseOnCancel: true,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(baseCtx context.Context) {
					acquireTimeout.Stop()
					e.resetReEntry()
					e.isLeader.Store(true)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection(%s): Callback Started leading",
						e.name)
				},
				OnStoppedLeading: func() {
					e.isLeader.Store(false)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection(%s): Callback Stopped leading",
						e.name)
				},
				OnNewLeader: func(identity string) {
					acquireTimeout.Stop()
					e.identity.Store(identity)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection(%s): Callback New leader "+
						"elected: %s", e.name, identity)
				},
			},
		}

		// Start the leader election in a separate goroutine
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			leaderelection.RunOrDie(baseCtx, lec)
			acquireTimeout.Stop()
			e.running.Store(false)
			e.isLeader.Store(false)
			e.identity.Store("")
			// Re-enter with a delay to pick up fresh kubeconfig/certs. If
			// the election was stopped meanwhile, the handler sees
			// contend()==false and skips.
			delay := z.scheduleReEntry(e)
			log.Noticef("handleLeaderElection(%s): Leader election routine exited, "+
				"re-entering in %v", e.name, delay)
		}()
		e.running.Store(true)
		z.publishLeaderElectionChange()
		log.Noticef("handleLeaderElection(%s): Started leader election routine for %s",
			e.name, z.nodeName)
	}
}

// controllerStatusDebounce is how long ConfigGetStatus has to stay at a
// failure value before the elections stop. It exceeds ConfigInterval's 60s
// maximum, so no single failed poll can stop them, and losing the controller
// does not call for a sub-minute reaction.
const controllerStatusDebounce = 90 * time.Second

// cancelElectionStop drops a pending debounced stop. Main loop only.
func (z *zedkube) cancelElectionStop() {
	if z.electionStopTimer != nil {
		z.electionStopTimer.Stop()
		z.electionStopTimer = nil
	}
}

// scheduleElectionStop stops the elections once the controller has stayed
// unreachable for controllerStatusDebounce.
func (z *zedkube) scheduleElectionStop() {
	z.scheduleElectionStopAfter(controllerStatusDebounce)
}

// scheduleElectionStopAfter is scheduleElectionStop with the delay supplied,
// so a test can drive the timer without waiting out the real debounce. Main
// loop only; the timer's own callback touches nothing but atomics and
// non-blocking channels.
func (z *zedkube) scheduleElectionStopAfter(delay time.Duration) {
	if z.electionStopTimer != nil {
		return // already counting down
	}
	z.electionStopTimer = time.AfterFunc(delay, func() {
		log.Noticef("handleControllerStatusChange: controller unreachable "+
			"for %v, stopping elections", delay)
		z.setElectionsShouldRun(false)
	})
}

// setElectionsShouldRun drives every election's desired state and wakes each
// handler.
func (z *zedkube) setElectionsShouldRun(run bool) {
	for _, e := range z.elections {
		e.shouldRun.Store(run)
		e.notify()
	}
}

func (z *zedkube) handleControllerStatusChange(status *types.ZedAgentStatus) {
	configStatus := status.ConfigGetStatus
	// Act on a real transition only. ZedAgentStatus is published for many
	// reasons, and zedagent arms ConfigGetFail before every request, so a
	// publish driven by an unrelated field can carry a transient failure.
	// nodeagent guards the same field the same way.
	if z.lastConfigGetStatus == configStatus {
		return
	}
	log.Noticef("handleControllerStatusChange: status %v -> %v",
		z.lastConfigGetStatus, configStatus)
	z.lastConfigGetStatus = configStatus

	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved:
		z.cancelElectionStop()
		z.setElectionsShouldRun(true)
	case types.ConfigGetTemporaryFail:
		// Set only while an image update is in progress. Keep contending:
		// giving up a lease during a baseos update is not what a temporary
		// failure asks for.
		log.Noticef("handleControllerStatusChange: temporary failure, " +
			"elections left running")
	default:
		z.scheduleElectionStop()
	}
}

func (z *zedkube) publishLeaderElectionChange() {
	stats := z.statsElection
	appOp := z.appOpElection
	info := types.KubeLeaderElectInfo{
		InLeaderElection:    stats.inElection.Load(),
		IsStatsLeader:       stats.isLeader.Load(),
		ElectionRunning:     stats.running.Load(),
		LeaderIdentity:      stats.identityString(),
		IsAppOpLeader:       appOp.isLeader.Load(),
		AppOpLeaderIdentity: appOp.identityString(),
	}
	// pubsub already drops an unchanged item, so LatestChange must not be
	// stamped unless something else moved -- stamping it on every call is
	// what makes this topic republish with no state change. Two callers
	// racing here can still publish twice, which is what happens today
	// anyway; the point is that a quiet election stops republishing.
	if last, err := z.pubLeaderElectInfo.Get("global"); err == nil {
		if prev, ok := last.(types.KubeLeaderElectInfo); ok {
			prev.LatestChange = info.LatestChange
			if prev == info {
				return
			}
		}
	}
	info.LatestChange = time.Now()
	z.pubLeaderElectInfo.Publish("global", info)
}
