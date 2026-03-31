// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const retryDelay = 5 * time.Minute

// notifyElection wakes up handleLeaderElection to act on the latest
// value of electionShouldRun. Non-blocking: if a notification is
// already pending, the handler will see the latest value anyway.
func (z *zedkube) notifyElection() {
	select {
	case z.electionNotifyCh <- struct{}{}:
	default:
	}
}

func (z *zedkube) handleLeaderElection() {
	var (
		cancelFunc context.CancelFunc
		wg         sync.WaitGroup
	)

	// stopElection cancels the running election goroutine and blocks until
	// it fully exits. After this call, all goroutine-owned state
	// (isKubeStatsLeader, leaderIdentity, electionFuncRunning) is cleaned up.
	stopElection := func() {
		if cancelFunc != nil {
			log.Noticef("handleLeaderElection: cancelling leader election")
			cancelFunc()
			cancelFunc = nil
			wg.Wait()
		}
	}

	for {
		log.Noticef("handleLeaderElection: Waiting for signal")
		<-z.electionNotifyCh

		if !z.electionShouldRun.Load() {
			// Stop requested — cancel, wait for goroutine to finish,
			// then update state and publish once with final values.
			stopElection()
			z.inKubeLeaderElection.Store(false)
			z.publishLeaderElectionChange()
			log.Noticef("handleLeaderElection: Stopped")
			continue
		}

		// Start requested
		z.inKubeLeaderElection.Store(true)

		// If the election goroutine is still running, nothing to do
		if z.electionFuncRunning.Load() {
			log.Noticef("handleLeaderElection: Election goroutine still running, skip")
			continue
		}

		// Create a cancelable context and start a timer that cancels it
		// if the lease is not acquired or a leader is not observed within 5 minutes
		// (e.g., due to failing connection caused by stale TLS certificates).
		// The timer is stopped once OnStartedLeading or OnNewLeader is triggered.
		baseCtx, cancel := context.WithCancel(context.Background())
		cancelFunc = cancel
		acquireTimeout := time.AfterFunc(retryDelay, func() {
			log.Noticef("handleLeaderElection: failed to acquire or observe lease " +
				"within 5 min, cancelling")
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
			log.Errorf("handleLeaderElection: can’t get clientset %v, retry in 5 min", err)
			z.publishLeaderElectionChange()
			time.AfterFunc(retryDelay, z.notifyElection)
			continue
		}

		// Create a new lease lock
		lock := &resourcelock.LeaseLock{
			LeaseMeta: metav1.ObjectMeta{
				Name:      "eve-kube-stats-leader",
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
					z.isKubeStatsLeader.Store(true)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection: Callback Started leading")
				},
				OnStoppedLeading: func() {
					z.isKubeStatsLeader.Store(false)
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection: Callback Stopped leading")
				},
				OnNewLeader: func(identity string) {
					acquireTimeout.Stop()
					z.leaderIdentity = identity
					z.publishLeaderElectionChange()
					log.Noticef("handleLeaderElection: Callback New leader elected: %s", identity)
				},
			},
		}

		// Start the leader election in a separate goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			leaderelection.RunOrDie(baseCtx, lec)
			acquireTimeout.Stop()
			z.electionFuncRunning.Store(false)
			z.isKubeStatsLeader.Store(false)
			z.leaderIdentity = ""
			log.Noticef("handleLeaderElection: Leader election routine exited")
			z.publishLeaderElectionChange()
			// Schedule a retry with delay to pick up fresh kubeconfig/certs.
			// If election was stopped in the meantime, the handler will see
			// electionShouldRun=false and skip.
			time.AfterFunc(retryDelay, func() {
				log.Noticef("handleLeaderElection: retry timer fired")
				z.notifyElection()
			})
		}()
		z.electionFuncRunning.Store(true)
		z.publishLeaderElectionChange()
		log.Noticef("handleLeaderElection: Started leader election routine for %s", z.nodeName)
	}
}

func (z *zedkube) handleControllerStatusChange(status *types.ZedAgentStatus) {
	configStatus := status.ConfigGetStatus
	log.Noticef("handleControllerStatusChange: status %v", configStatus)
	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved:
		z.electionShouldRun.Store(true)
	default:
		z.electionShouldRun.Store(false)
	}
	z.notifyElection()
}

func (z *zedkube) publishLeaderElectionChange() {
	// Publish the change in leader
	leaderElectinfo := types.KubeLeaderElectInfo{
		InLeaderElection: z.inKubeLeaderElection.Load(),
		IsStatsLeader:    z.isKubeStatsLeader.Load(),
		ElectionRunning:  z.electionFuncRunning.Load(),
		LeaderIdentity:   z.leaderIdentity,
		LatestChange:     time.Now(),
	}
	z.pubLeaderElectInfo.Publish("global", leaderElectinfo)
}
