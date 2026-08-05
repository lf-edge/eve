// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// TestDeriveMembershipPrecedence pins the order the overlapping cases
// resolve in. They genuinely overlap — a node mid-rollback still has
// its cluster markers on disk — so "which one wins" is the whole
// contract, and getting it wrong would mislabel exactly the states we
// spent the day unable to see.
func TestDeriveMembershipPrecedence(t *testing.T) {
	if _, err := os.Stat(string(state.ConvertToSingleNode)); !os.IsNotExist(err) {
		t.Skipf("host carries a real %s marker", state.ConvertToSingleNode)
	}
	if _, err := os.Stat(string(state.TransitionToCluster)); !os.IsNotExist(err) {
		t.Skipf("host carries a real %s marker", state.TransitionToCluster)
	}
	if _, err := os.Stat(string(state.EdgeNodeClusterMode)); !os.IsNotExist(err) {
		t.Skipf("host carries a real %s marker", state.EdgeNodeClusterMode)
	}

	// With no markers and no cluster status, a node is standalone.
	d := newTestDaemon()
	if got := d.deriveMembership(); got != MembershipSingle {
		t.Errorf("bare node: deriveMembership = %q, want %q", got, MembershipSingle)
	}

	// The FSM running the cluster→single transition reports Leaving
	// even before any marker changes — that is the window in which
	// EVE tears the cluster IP down, and it needs to be visible.
	d = newTestDaemon()
	d.state = StateClusterTransition
	d.restartReason = restartClusterToSingle
	if got := d.deriveMembership(); got != MembershipLeaving {
		t.Errorf("mid cluster→single: deriveMembership = %q, want %q",
			got, MembershipLeaving)
	}

	// A single→cluster transition in flight is not Leaving.
	d = newTestDaemon()
	d.state = StateClusterTransition
	d.restartReason = restartSingleToCluster
	if got := d.deriveMembership(); got == MembershipLeaving {
		t.Error("single→cluster transition reported as Leaving")
	}
}

// TestBuildStatusCarriesTheFSM checks the snapshot actually reflects
// the daemon rather than returning zero values — the failure mode
// would be a status topic that always looks the same, which is what we
// had.
func TestBuildStatusCarriesTheFSM(t *testing.T) {
	d := newTestDaemon()
	d.state = StateWaitK3sReady
	d.phase = PhaseRecycle
	d.setTransitionStep("multus-reset")

	s := d.buildStatus()

	if s.State != StateWaitK3sReady.String() {
		t.Errorf("State = %q, want %q", s.State, StateWaitK3sReady.String())
	}
	if s.Phase != PhaseRecycle.String() {
		t.Errorf("Phase = %q, want %q", s.Phase, PhaseRecycle.String())
	}
	if s.TransitionStep != "multus-reset" {
		t.Errorf("TransitionStep = %q, want %q", s.TransitionStep, "multus-reset")
	}
	if s.Membership == "" {
		t.Error("Membership empty — the field exists to always say something")
	}
	if s.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not stamped; a consumer cannot tell this from a stale publication")
	}
}
