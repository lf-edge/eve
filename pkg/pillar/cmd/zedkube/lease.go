// Copyright (c) 2024 Zededa, Inc.
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
	for {
		log.Functionf("handleLeaderElection: Waiting for signal") // XXX
		select {
		case <-z.electionStartCh:

			// Create a cancellable context
			baseCtx, cancel := context.WithCancel(context.Background())
			cancelFunc = cancel

			clientset, err := getKubeClientSet()
			if err != nil {
				z.inKubeLeaderElection = false
				log.Errorf("handleLeaderElection: can't get clientset %v", err)
				return
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
				LeaseDuration:   15 * time.Second,
				RenewDeadline:   10 * time.Second,
				RetryPeriod:     2 * time.Second,
				ReleaseOnCancel: true,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: func(baseCtx context.Context) {
						z.isKubeStatsLeader = true
						log.Functionf("handleLeaderElection: Started leading")
					},
					OnStoppedLeading: func() {
						z.isKubeStatsLeader = false
						log.Functionf("handleLeaderElection: Stopped leading")
					},
					OnNewLeader: func(identity string) {
						log.Functionf("handleLeaderElection: New leader elected: %s", identity)
					},
				},
			}

			// Start the leader election in a separate goroutine
			go leaderelection.RunOrDie(baseCtx, lec)
			log.Noticef("handleLeaderElection: Started leader election for %s", z.nodeName)

		case <-z.electionStopCh:
			z.isKubeStatsLeader = false
			z.inKubeLeaderElection = false
			log.Noticef("handleLeaderElection: Stopped leading signal received")
			if cancelFunc != nil {
				cancelFunc()
				cancelFunc = nil
			}
		}
	}
}

// SignalStartLeaderElection - to signal the start of leader election
func (z *zedkube) SignalStartLeaderElection() {
	z.inKubeLeaderElection = true
	select {
	case z.electionStartCh <- struct{}{}:
		log.Functionf("SignalStartLeaderElection: Signal sent successfully")
	default:
		log.Warningf("SignalStartLeaderElection: Channel is full, signal not sent")
	}
}

// SignalStopLeaderElection - to signal the stop of leader election
func (z *zedkube) SignalStopLeaderElection() {
	select {
	case z.electionStopCh <- struct{}{}:
		log.Functionf("SignalStopLeaderElection: Signal sent successfully")
	default:
		log.Warningf("SignalStopLeaderElection: Channel is full, signal not sent")
	}
}

func (z *zedkube) handleControllerStatusChange(status *types.ZedAgentStatus) {
	configStatus := status.ConfigGetStatus

	log.Functionf("handleControllerStatusChange: Leader enter, status %v", configStatus)
	switch configStatus {
	case types.ConfigGetSuccess, types.ConfigGetReadSaved: // either read success or read from saved config
		if !z.inKubeLeaderElection {
			z.SignalStartLeaderElection()
		}
	default:
		if z.inKubeLeaderElection {
			z.SignalStopLeaderElection()
		}
	}
}
