// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/encstatus"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeinitstatus"
	"github.com/lf-edge/eve/pkg/kube/kube-init/monitor"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Membership names where the node sits in the single↔cluster lifecycle.
// Derived on demand from markers plus FSM state; nothing stores it, so
// there is no second copy to drift.
const (
	MembershipSingle      = "Single"
	MembershipJoinPending = "JoinPending"
	MembershipJoining     = "Joining"
	MembershipMember      = "Member"
	MembershipLeaving     = "Leaving"
	MembershipRestoring   = "Restoring"
	MembershipUnknown     = "Unknown"
)

// deriveMembership answers "what is this node, cluster-wise" from state
// the daemon already holds. Order matters — the cases overlap and the
// first match wins:
//
//  1. Restoring: convert-to-single-node is on disk, so the next boot
//     (or this one, mid-restore) is putting the pre-cluster /var/lib
//     back. Beats everything; the markers underneath it still describe
//     the cluster the node is leaving.
//  2. Leaving: the FSM is running the cluster→single transition now.
//  3. Joining: the transition-to-cluster marker is on disk, meaning a
//     join is in flight and the watchdog is watching it.
//  4. Member: cluster mode marked and a live EdgeNodeClusterStatus.
//  5. JoinPending: a cluster status has arrived but the node has not
//     entered cluster mode yet — the interval that was invisible when
//     a node stalled here for eleven minutes.
//  6. Single: none of the above.
func (d *daemon) deriveMembership() string {
	if converting, err := state.IsConvertToSingleNode(); err == nil && converting {
		return MembershipRestoring
	}
	if d.state == StateClusterTransition && d.restartReason == restartClusterToSingle {
		return MembershipLeaving
	}
	if joining, err := state.IsMarked(state.TransitionToCluster); err == nil && joining {
		return MembershipJoining
	}
	inCluster, err := state.IsMarked(state.EdgeNodeClusterMode)
	if err != nil {
		return MembershipUnknown
	}
	switch {
	case inCluster && encstatus.Present():
		return MembershipMember
	case encstatus.Present():
		return MembershipJoinPending
	case inCluster:
		// Cluster mode marked but no live status: the controller has
		// withdrawn and the conversion has not started yet.
		return MembershipLeaving
	}
	return MembershipSingle
}

// buildStatus snapshots everything worth publishing about the daemon
// right now. Cheap — marker stats and cached pubsub reads — so it is
// safe to call on every FSM transition.
func (d *daemon) buildStatus() kubeinitstatus.KubeInitStatus {
	initialized, _ := state.IsInitialized()
	s := kubeinitstatus.KubeInitStatus{
		AllComponentsInitialized: initialized,
		State:                    d.state.String(),
		Phase:                    d.phase.String(),
		Membership:               d.deriveMembership(),
		TransitionStep:           d.getTransitionStep(),
		JoinWatchdogActive:       monitor.JoinWatchdogActive(),
		UpdatedAt:                time.Now(),
	}
	if d.lastError != nil {
		s.LastError = d.lastError.Error()
	}
	// Cluster identity comes from the live status when there is one;
	// a standalone node simply has none to report.
	if cs, err := k3s.GetClusterStatus(); err == nil && cs != nil {
		s.ClusterID = cs.ClusterID
		if cs.IsBootstrapNode {
			s.Role = "Bootstrap"
		} else {
			s.Role = "Server"
		}
	}
	return s
}

// publishStatus pushes the current snapshot onto the KubeInitStatus
// topic. Best-effort: before the publisher is registered (very early
// boot) this fails, and the caller has nothing useful to do about it.
func (d *daemon) publishStatus() {
	if !d.statusPublishReady {
		return
	}
	_ = kubeinitstatus.Publish(d.buildStatus())
}
