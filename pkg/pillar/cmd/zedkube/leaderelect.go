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

const (
	// statsLeaseName picks the node that reports cluster stats, prunes stale
	// nodes, and nudges a stuck failover. Any node can do that work.
	statsLeaseName = "eve-kube-stats-leader"
	// appStartLeaseName picks the node that submits an app start when the
	// app's own designated node cannot. The tie-breaker node must never hold
	// this lease: it gets no AppInstanceConfig, so it cannot start any app,
	// and while it held the lease no node that can start apps would.
	appStartLeaseName = "eve-app-start-leader"
)

// leaderElection holds the state of one leader election. Zedkube runs two,
// on two separate Lease objects, because the two roles need different nodes.
type leaderElection struct {
	// leaseName is the Kubernetes Lease object to contend for.
	leaseName string
	// notifyCh wakes the handler to act on the latest shouldRun and eligible.
	notifyCh chan struct{}
	// shouldRun is the desired state, from the controller connection state.
	shouldRun atomic.Bool
	// eligible reports whether this node may hold this lease at all.
	eligible atomic.Bool
	// The fields below belong to the handler and its election goroutine.
	inElection  atomic.Bool
	funcRunning atomic.Bool
	isLeader    atomic.Bool
	identity    string
}

func newLeaderElection(leaseName string, eligible bool) *leaderElection {
	e := &leaderElection{
		leaseName: leaseName,
		notifyCh:  make(chan struct{}, 1),
	}
	// The app-start lease starts ineligible, until the cluster config and
	// this node's own UUID are both known. A node that cannot decide must
	// not hold that lease: the tie-breaker cannot start an app, and while
	// it holds the lease no node that can start apps will. Nothing is lost
	// by waiting, because the app's designated node has its own path.
	e.eligible.Store(eligible)
	return e
}

// notify wakes up handleLeaderElection to act on the latest value of
// shouldRun and eligible. Non-blocking: if a notification is already
// pending, the handler will see the latest values anyway.
func (e *leaderElection) notify() {
	select {
	case e.notifyCh <- struct{}{}:
	default:
	}
}

// wanted reports whether this node should hold this lease right now.
func (e *leaderElection) wanted() bool {
	return e.shouldRun.Load() && e.eligible.Load()
}

func (z *zedkube) handleLeaderElection(e *leaderElection) {
	var (
		cancelFunc context.CancelFunc
		wg         sync.WaitGroup
	)

	// stopElection cancels the running election goroutine and blocks until
	// it fully exits. After this call, all goroutine-owned state
	// (isLeader, identity, funcRunning) is cleaned up. The election sets
	// ReleaseOnCancel, so a cancel also releases the lease and another node
	// can take it without waiting for the lease to expire.
	stopElection := func() {
		if cancelFunc != nil {
			log.Noticef("handleLeaderElection(%s): cancelling leader election",
				e.leaseName)
			cancelFunc()
			cancelFunc = nil
			wg.Wait()
		}
	}

	for {
		log.Noticef("handleLeaderElection(%s): Waiting for signal", e.leaseName)
		<-e.notifyCh

		if !e.wanted() {
			// Stop requested — cancel, wait for goroutine to finish,
			// then update state and publish once with final values.
			stopElection()
			e.inElection.Store(false)
			z.publishLeaderElectionChange()
			log.Noticef("handleLeaderElection(%s): Stopped", e.leaseName)
			continue
		}

		// Start requested
		e.inElection.Store(true)

		// If the election goroutine is still running, nothing to do
		if e.funcRunning.Load() {
			log.Noticef("handleLeaderElection(%s): Election goroutine still running, skip",
				e.leaseName)
			continue
		}

		// Create a cancelable context and start a timer that cancels it
		// if the lease is not acquired or a leader is not observed within 5 minutes
		// (e.g., due to failing connection caused by stale TLS certificates).
		// The timer is stopped once OnStartedLeading or OnNewLeader is triggered.
		baseCtx, cancel := context.WithCancel(context.Background())
		cancelFunc = cancel
		acquireTimeout := time.AfterFunc(retryDelay, func() {
			log.Noticef("handleLeaderElection(%s): failed to acquire or observe "+
				"lease within 5 min, cancelling", e.leaseName)
			// No need to worry about a race between cancel() here and cancelFunc()
			// potentially being triggered concurrently by stopElection.
			// In Go, calling a context’s cancel function multiple times is safe
			// and has no effect after the first call.
			cancel()
		})

		// Always create a fresh clientset to pick up any kubeconfig
		// changes (e.g. TLS cert regeneration during cluster join)
		clientset, err := getKubeClientSet()
		if err != nil {
			acquireTimeout.Stop()
			cancel()
			cancelFunc = nil
			log.Errorf("handleLeaderElection(%s): can’t get clientset %v, retry in 5 min",
				e.leaseName, err)
			z.publishLeaderElectionChange()
			time.AfterFunc(retryDelay, e.notify)
			continue
		}

		// Create a new lease lock
		lock := &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      e.leaseName,
				Namespace: kubeapi.EVEKubeNameSpace,
			},
			Client: clientset.CoordinationV1(),
			LockConfig: resourcelock.ResourceLockConfig{
				Identity: z.nodeName,
			},
		}

		// Define the leader election configuration
		lec := leaderelection.LeaderElectionConfig{
			Lock:            lock,
			LeaseDuration:   300 * time.Second,
			RenewDeadline:   180 * time.Second,
			RetryPeriod:     15 * time.Second,
			ReleaseOnCancel: true,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(baseCtx context.Context) {
					acquireTimeout.Stop()
					e.isLeader.Store(true)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection(%s): Callback Started leading",
						e.leaseName)
				},
				OnStoppedLeading: func() {
					e.isLeader.Store(false)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection(%s): Callback Stopped leading",
						e.leaseName)
				},
				OnNewLeader: func(identity string) {
					acquireTimeout.Stop()
					e.identity = identity
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection(%s): Callback New leader elected: %s",
						e.leaseName, identity)
				},
			},
		}

		// Start the leader election in a separate goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			leaderelection.RunOrDie(baseCtx, lec)
			acquireTimeout.Stop()
			e.funcRunning.Store(false)
			e.isLeader.Store(false)
			e.identity = ""
			log.Noticef("handleLeaderElection(%s): Leader election routine exited",
				e.leaseName)
			z.publishLeaderElectionChange()
			// Schedule a retry with delay to pick up fresh kubeconfig/certs.
			// If election was stopped in the meantime, the handler will see
			// that it is no longer wanted and skip.
			time.AfterFunc(retryDelay, func() {
				log.Noticef("handleLeaderElection(%s): retry timer fired", e.leaseName)
				e.notify()
			})
		}()
		e.funcRunning.Store(true)
		z.publishLeaderElectionChange()
		log.Noticef("handleLeaderElection(%s): Started leader election routine for %s",
			e.leaseName, z.nodeName)
	}
}

func (z *zedkube) handleControllerStatusChange(status *types.ZedAgentStatus) {
	configStatus := status.ConfigGetStatus
	log.Noticef("handleControllerStatusChange: status %v", configStatus)
	var shouldRun bool
	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved:
		shouldRun = true
	default:
		shouldRun = false
	}
	for _, e := range []*leaderElection{z.statsElection, z.appStartElection} {
		e.shouldRun.Store(shouldRun)
		e.notify()
	}
}

// refreshAppStartEligibility re-reads the tie-breaker from the cluster config
// and wakes the app-start election if this node's eligibility changed. The
// tie-breaker can be set after this node already holds the lease, and the
// election renews on its own until cancelled, so a node that becomes the
// tie-breaker has to give the lease up here.
// It needs z.nodeuuid, so every caller must run after that is resolved. An
// empty or unparsable node UUID reads as "not the tie-breaker", which would
// wrongly make a tie-breaker eligible.
func (z *zedkube) refreshAppStartEligibility() {
	eligible := !z.clusterConfig.IsTieBreakerNode(z.nodeuuid)
	changed := z.appStartElection.eligible.Swap(eligible) != eligible
	// Log every call, not only a change. The first call decides whether this
	// node ever contends, and a silent no-change made a live failure on a
	// tie-breaker node hard to read.
	log.Noticef("refreshAppStartEligibility: node %s app-start eligible %t, changed %t",
		z.nodeuuid, eligible, changed)
	if changed {
		z.appStartElection.notify()
	}
}

func (z *zedkube) publishLeaderElectionChange() {
	// Publish the change in leader
	leaderElectinfo := types.KubeLeaderElectInfo{
		InLeaderElection:       z.statsElection.inElection.Load(),
		IsStatsLeader:          z.statsElection.isLeader.Load(),
		ElectionRunning:        z.statsElection.funcRunning.Load(),
		LeaderIdentity:         z.statsElection.identity,
		IsAppStartLeader:       z.appStartElection.isLeader.Load(),
		AppStartLeaderIdentity: z.appStartElection.identity,
		LatestChange:           time.Now(),
	}
	z.pubLeaderElectInfo.Publish("global", leaderElectinfo)
}
