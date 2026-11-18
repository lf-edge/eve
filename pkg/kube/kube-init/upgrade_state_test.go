// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/update"
)

// TestWaitUpgradeTransitions pins where the component update pass sits
// in the FSM and what it tells pillar. WAIT_UPGRADE is entered from
// WAIT_K3S_READY only on the non-first-boot path and only when a pass
// is pending; it always ends in RUNNING, with ComponentsReady reporting
// whether the pass succeeded.
func TestWaitUpgradeTransitions(t *testing.T) {
	ctx := context.Background()
	pending := func() bool { return true }
	notPending := func() bool { return false }

	tests := []struct {
		name            string
		initState       State
		initPhase       Phase
		pendingFn       func() bool
		event           Event
		wantState       State
		wantReady       bool
		wantUpdateState string
	}{
		{
			name:            "pass pending -> WAIT_UPGRADE, not ready yet",
			initState:       StateWaitK3sReady,
			initPhase:       PhaseSteady,
			pendingFn:       pending,
			event:           Event{Type: EvK3sReady},
			wantState:       StateWaitUpgrade,
			wantUpdateState: updateStateInProgress,
		},
		{
			name:            "no pass pending -> RUNNING, ready",
			initState:       StateWaitK3sReady,
			initPhase:       PhaseSteady,
			pendingFn:       notPending,
			event:           Event{Type: EvK3sReady},
			wantState:       StateRunning,
			wantReady:       true,
			wantUpdateState: updateStateNone,
		},
		{
			name:            "first boot deploys before any pass",
			initState:       StateWaitK3sReady,
			initPhase:       PhaseFirstBoot,
			pendingFn:       pending,
			event:           Event{Type: EvK3sReady},
			wantState:       StateDeploying,
			wantUpdateState: updateStateNone,
		},
		{
			name:            "pass done -> RUNNING, ready",
			initState:       StateWaitUpgrade,
			event:           Event{Type: EvUpgradeDone},
			wantState:       StateRunning,
			wantReady:       true,
			wantUpdateState: updateStateCompleted,
		},
		{
			name:      "pass failed -> RUNNING, not ready, failed",
			initState: StateWaitUpgrade,
			event: Event{Type: EvError,
				Err: fmt.Errorf("update component longhorn: %w", update.ErrUpdateFailed)},
			wantState:       StateRunning,
			wantUpdateState: updateStateFailed,
		},
		{
			name:      "pass deferred -> RUNNING, ready, deferred",
			initState: StateWaitUpgrade,
			event: Event{Type: EvError,
				Err: fmt.Errorf("update component longhorn: %w", update.ErrUpdateDeferred)},
			wantState:       StateRunning,
			wantReady:       true,
			wantUpdateState: updateStateDeferred,
		},
		{
			name:            "transient error retries in place",
			initState:       StateWaitUpgrade,
			event:           Event{Type: EvError, Err: errors.New("cluster not ready")},
			wantState:       StateWaitUpgrade,
			wantUpdateState: updateStateNone,
		},
		{
			name:            "k3s exit -> BACKOFF",
			initState:       StateWaitUpgrade,
			event:           Event{Type: EvK3sExited},
			wantState:       StateBackoff,
			wantUpdateState: updateStateNone,
		},
		{
			name:            "restart request is queued, not acted on",
			initState:       StateWaitUpgrade,
			event:           Event{Type: EvSocketRestart},
			wantState:       StateWaitUpgrade,
			wantUpdateState: updateStateNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDaemon()
			d.state = tt.initState
			d.phase = tt.initPhase
			d.passPendingFn = tt.pendingFn

			d.handleEvent(ctx, tt.event)

			if d.state != tt.wantState {
				t.Errorf("state = %v, want %v", d.state, tt.wantState)
			}
			status := d.buildStatus()
			if status.ComponentsReady != tt.wantReady {
				t.Errorf("ComponentsReady = %v, want %v",
					status.ComponentsReady, tt.wantReady)
			}
			if status.UpdateState != tt.wantUpdateState {
				t.Errorf("UpdateState = %q, want %q",
					status.UpdateState, tt.wantUpdateState)
			}
			wantError := tt.wantUpdateState == updateStateFailed ||
				tt.wantUpdateState == updateStateDeferred
			if (status.UpdateError != "") != wantError {
				t.Errorf("UpdateError = %q with UpdateState %q",
					status.UpdateError, status.UpdateState)
			}
		})
	}
}

// TestFailedPassIsNotPendingAgain pins that a k3s restart after a
// failed pass goes straight to RUNNING and keeps reporting the failure,
// rather than re-entering WAIT_UPGRADE or turning ready.
func TestFailedPassIsNotPendingAgain(t *testing.T) {
	ctx := context.Background()
	d := newTestDaemon()
	d.state = StateWaitUpgrade
	d.handleEvent(ctx, Event{Type: EvError,
		Err: fmt.Errorf("wait ready: %w", update.ErrUpdateFailed)})
	if d.componentPassPending() {
		t.Fatal("a failed pass is reported as pending")
	}

	d.state = StateWaitK3sReady
	d.phase = PhaseSteady
	d.handleEvent(ctx, Event{Type: EvK3sReady})
	if d.state != StateRunning {
		t.Fatalf("state = %v, want RUNNING", d.state)
	}
	if status := d.buildStatus(); status.ComponentsReady ||
		status.UpdateState != updateStateFailed {
		t.Errorf("ComponentsReady = %v, UpdateState = %q after a failed pass",
			status.ComponentsReady, status.UpdateState)
	}
}

// TestComponentsReadyIsLatched pins that leaving RUNNING, as every k3s
// restart does, does not take ComponentsReady back.
func TestComponentsReadyIsLatched(t *testing.T) {
	ctx := context.Background()
	d := newTestDaemon()
	d.state = StateWaitUpgrade
	d.handleEvent(ctx, Event{Type: EvUpgradeDone})
	d.handleEvent(ctx, Event{Type: EvK3sExited})
	if d.state != StateBackoff {
		t.Fatalf("state = %v, want BACKOFF", d.state)
	}
	if !d.buildStatus().ComponentsReady {
		t.Error("ComponentsReady dropped when k3s exited")
	}
}
