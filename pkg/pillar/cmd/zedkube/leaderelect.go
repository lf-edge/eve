// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package zedkube

import (
	"context"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func (z *zedkube) handleLeaderElection() {
	var cancelFunc context.CancelFunc
	// If we can not perform the leader election, due to kubernetes connection issues
	// at the moment, we will retry in 5 minutes
	retryTimer := time.NewTimer(0)
	retryTimer.Stop() // Ensure the timer is stopped initially
	retryTimerStarted := false
	for {
		log.Noticef("handleLeaderElection: Waiting for signal") // XXX
		select {
		case <-z.electionStartCh:

			// Create a cancellable context
			baseCtx, cancel := context.WithCancel(context.Background())
			cancelFunc = cancel

			clientset, err := getKubeClientSet()
			if err != nil {
				z.inKubeLeaderElection.Store(false)
				z.publishLeaderElectionChange()
				log.Errorf("handleLeaderElection: can't get clientset %v, retry in 5 min", err)
				retryTimer.Reset(5 * time.Minute)
				retryTimerStarted = true
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
						z.leaderIdentity = identity
						z.publishLeaderElectionChange()
						log.Noticef("handleLeaderElection: Callback New leader elected: %s", identity)
					},
				},
			}

			// Start the leader election in a separate goroutine
			go func() {
				leaderelection.RunOrDie(baseCtx, lec)
				z.electionFuncRunning.Store(false)
				log.Noticef("handleLeaderElection: Leader election routine exited")
				if z.inKubeLeaderElection.Load() {
					retryTimer.Reset(5 * time.Minute)
					retryTimerStarted = true
					log.Noticef("handleLeaderElection: We should be inElection, retry in 5 min")
				}
				z.publishLeaderElectionChange()
			}()
			z.electionFuncRunning.Store(true)
			z.publishLeaderElectionChange()
			log.Noticef("handleLeaderElection: Started leader election routine for %s", z.nodeName)

		case <-z.electionStopCh:
			z.isKubeStatsLeader.Store(false)
			z.inKubeLeaderElection.Store(false)
			z.leaderIdentity = ""
			z.publishLeaderElectionChange()
			log.Noticef("handleLeaderElection: Stopped leading signal received")
			if retryTimerStarted {
				retryTimer.Stop()
				retryTimerStarted = false
			}

			if cancelFunc != nil {
				log.Noticef("handleLeaderElection: Stopped. cancelling leader election")
				cancelFunc()
				cancelFunc = nil
			}

		case <-retryTimer.C:
			log.Noticef("Retrying failed leader election")
			sub := z.subZedAgentStatus
			items := sub.GetAll()
			for _, item := range items {
				status := item.(types.ZedAgentStatus)
				z.handleControllerStatusChange(&status)
				break
			}
			retryTimerStarted = false
		}
	}
}

// SignalStartLeaderElection - Function to signal the start of leader election
func (z *zedkube) SignalStartLeaderElection() {
	z.inKubeLeaderElection.Store(true)
	select {
	case z.electionStartCh <- struct{}{}:
		log.Noticef("SignalStartLeaderElection: Signal sent successfully")
	default:
		log.Warningf("SignalStartLeaderElection: Channel is full, signal not sent")
	}
}

// SignalStopLeaderElection - Function to signal the stop of leader election
func (z *zedkube) SignalStopLeaderElection() {
	select {
	case z.electionStopCh <- struct{}{}:
		log.Noticef("SignalStopLeaderElection: Signal sent successfully")
	default:
		log.Warningf("SignalStopLeaderElection: Channel is full, signal not sent")
	}
}

func (z *zedkube) handleControllerStatusChange(status *types.ZedAgentStatus) {
	configStatus := status.ConfigGetStatus

	log.Noticef("handleControllerStatusChange: Leader enter, status %v", configStatus)
	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved: // either read success or read from saved config
		if !z.inKubeLeaderElection.Load() {
			z.SignalStartLeaderElection()
		} else {
			log.Noticef("handleControllerStatusChange: start. Already in leader election, skip")
		}
	default:
		if z.inKubeLeaderElection.Load() {
			z.SignalStopLeaderElection()
		} else {
			log.Noticef("handleControllerStatusChange: default stop. Not in leader election, skip")
		}
	}
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
