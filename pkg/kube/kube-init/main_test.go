// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/deploy"
	"github.com/lf-edge/eve/pkg/kube/kube-init/monitor"
)

// newTestDaemon constructs a daemon whose enterStateFn is a no-op
// so handleEvent exercises the transition graph without launching
// real work. Production tests would use the live entry actions;
// these tests target the FSM table itself.
func newTestDaemon() *daemon {
	d := &daemon{
		backoff:      minBackoff,
		eventCh:      make(chan Event, 32),
		monRestartCh: make(chan monitor.RestartReason, 4),
	}
	d.enterStateFn = func(context.Context) {}
	return d
}

// TestTransitionTable is the FSM transition-graph contract test.
// Each row asserts: from state S with phase P and restart reason
// R, an event E moves us to state S' and (optionally) sets a
// derived field. Adding a transition without a matching row here
// is a smell — the next reviewer will want to know why.
func TestTransitionTable(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		initState  State
		initPhase  Phase
		initReason restartReason
		event      Event
		wantState  State
		checkFn    func(*testing.T, *daemon)
	}{
		// === INIT ===
		{
			name:      "Init/PrereqsDone->Installing",
			initState: StateInit,
			event:     Event{Type: EvPrereqsDone},
			wantState: StateInstalling,
		},
		{
			name:      "Init/Error stays in Init and records lastError",
			initState: StateInit,
			event:     Event{Type: EvError, Err: errors.New("fail")},
			wantState: StateInit,
			checkFn: func(t *testing.T, d *daemon) {
				if d.lastError == nil {
					t.Error("expected lastError to be set")
				}
			},
		},
		{
			name:      "Init/SocketRestart queues",
			initState: StateInit,
			event:     Event{Type: EvSocketRestart},
			wantState: StateInit,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil {
					t.Error("expected pending restart")
				}
			},
		},

		// === INSTALLING ===
		{
			name:      "Installing/InstallDone->StartingCtrd",
			initState: StateInstalling,
			event:     Event{Type: EvInstallDone},
			wantState: StateStartingCtrd,
		},
		{
			name:      "Installing/Error retries",
			initState: StateInstalling,
			event:     Event{Type: EvError, Err: errors.New("fail")},
			wantState: StateInstalling,
		},

		// === STARTING_CTRD ===
		{
			name:      "StartingCtrd/ContainerdReady->Configuring",
			initState: StateStartingCtrd,
			event:     Event{Type: EvContainerdReady},
			wantState: StateConfiguring,
		},
		{
			name:      "StartingCtrd/Error retries",
			initState: StateStartingCtrd,
			event:     Event{Type: EvError, Err: errors.New("fail")},
			wantState: StateStartingCtrd,
		},

		// === CONFIGURING ===
		{
			name:      "Configuring/ConfigureDone->StartingK3s",
			initState: StateConfiguring,
			event:     Event{Type: EvConfigureDone},
			wantState: StateStartingK3s,
		},

		// === STARTING_K3S ===
		{
			name:      "StartingK3s/K3sStarted+FirstBoot->Importing",
			initState: StateStartingK3s,
			initPhase: PhaseFirstBoot,
			event:     Event{Type: EvK3sStarted},
			wantState: StateImporting,
		},
		{
			// PhaseSteady is also the phase on the first boot of a
			// new EVE release, so it must reach Importing for the
			// external-boot-image re-tag; WaitK3sReady still follows
			// via EvImagesDone, keeping the health-worker goroutines
			// in enterRunning off a not-yet-reachable API server.
			// See the comment in handleStartingK3s.
			name:      "StartingK3s/K3sStarted+Restart->Importing",
			initState: StateStartingK3s,
			initPhase: PhaseSteady,
			event:     Event{Type: EvK3sStarted},
			wantState: StateImporting,
		},
		{
			name:      "StartingK3s/K3sStarted+Recycle->Importing",
			initState: StateStartingK3s,
			initPhase: PhaseRecycle,
			event:     Event{Type: EvK3sStarted},
			wantState: StateImporting,
		},
		{
			name:      "StartingK3s/K3sExited->Backoff",
			initState: StateStartingK3s,
			event:     Event{Type: EvK3sExited, Err: errors.New("crashed")},
			wantState: StateBackoff,
		},
		{
			name:      "StartingK3s/Error retries",
			initState: StateStartingK3s,
			event:     Event{Type: EvError, Err: errors.New("fail")},
			wantState: StateStartingK3s,
		},
		{
			name:      "StartingK3s/SocketRestart queues",
			initState: StateStartingK3s,
			event:     Event{Type: EvSocketRestart},
			wantState: StateStartingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil {
					t.Error("expected pending restart")
				}
			},
		},

		// === IMPORTING ===
		{
			name:      "Importing/ImagesDone->WaitK3sReady",
			initState: StateImporting,
			event:     Event{Type: EvImagesDone},
			wantState: StateWaitK3sReady,
		},
		{
			name:      "Importing/K3sExited->Backoff",
			initState: StateImporting,
			event:     Event{Type: EvK3sExited, Err: errors.New("died")},
			wantState: StateBackoff,
		},

		// === WAIT_K3S_READY ===
		{
			name:      "WaitK3sReady/K3sReady+FirstBoot->Deploying",
			initState: StateWaitK3sReady,
			initPhase: PhaseFirstBoot,
			event:     Event{Type: EvK3sReady},
			wantState: StateDeploying,
		},
		{
			name:      "WaitK3sReady/K3sReady+Restart->Running",
			initState: StateWaitK3sReady,
			initPhase: PhaseSteady,
			event:     Event{Type: EvK3sReady},
			wantState: StateRunning,
		},
		{
			name:      "WaitK3sReady/K3sReady+Recycle->Running",
			initState: StateWaitK3sReady,
			initPhase: PhaseRecycle,
			event:     Event{Type: EvK3sReady},
			wantState: StateRunning,
		},
		{
			name:      "WaitK3sReady/K3sExited->Backoff",
			initState: StateWaitK3sReady,
			event:     Event{Type: EvK3sExited},
			wantState: StateBackoff,
		},
		{
			// The deadlock this guards against: withdrawing the
			// cluster config takes the node's cluster IP away, so a
			// node waiting for readiness when it lands never becomes
			// Ready and never reaches RUNNING. Queueing the request
			// until RUNNING would queue it forever, so it has to be
			// acted on right here.
			name:      "WaitK3sReady/ClusterToSingle->ClusterTransition",
			initState: StateWaitK3sReady,
			event:     Event{Type: EvClusterToSingle},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartClusterToSingle {
					t.Errorf("restartReason = %v, want restartClusterToSingle",
						restartReasonString(d.restartReason))
				}
			},
		},
		{
			// Single→cluster genuinely needs a live k3s (token
			// rotation, multus re-apply), so it queues rather than
			// running here — but it must not be dropped, which is
			// what happened before the monitor outlived RUNNING.
			name:      "WaitK3sReady/SingleToCluster queues",
			initState: StateWaitK3sReady,
			event:     Event{Type: EvSingleToCluster},
			wantState: StateWaitK3sReady,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil {
					t.Fatal("expected pending restart")
				}
				if *d.pendingRestart != restartSingleToCluster {
					t.Errorf("pendingRestart = %v, want restartSingleToCluster",
						restartReasonString(*d.pendingRestart))
				}
			},
		},

		// === DEPLOYING ===
		{
			// The deploy hands off to SNAPSHOT, not RUNNING: /var/lib
			// holds k3s's datastore and must be copied with k3s stopped.
			// Phase must stay first-boot until the snapshot is on disk,
			// or the restart SNAPSHOT performs would skip it.
			name:      "Deploying/DeployDone->Snapshot keeping PhaseFirstBoot",
			initState: StateDeploying,
			initPhase: PhaseFirstBoot,
			event:     Event{Type: EvDeployDone},
			wantState: StateSnapshot,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseFirstBoot {
					t.Errorf("phase = %v, want PhaseFirstBoot until the snapshot lands", d.phase)
				}
				if d.lastError != nil {
					t.Errorf("lastError = %v, want nil (cleared on success)", d.lastError)
				}
			},
		},
		{
			name:      "Deploying/K3sExited->Backoff",
			initState: StateDeploying,
			event:     Event{Type: EvK3sExited},
			wantState: StateBackoff,
		},

		// === SNAPSHOT ===
		// EvStopDone is deliberately not table-tested: handleSnapshot
		// launches the real snapshot worker for it, which would copy the
		// host's /var/lib during a unit test.
		{
			// Stopping k3s is what SNAPSHOT asked for, so its exit must
			// not be mistaken for a crash and routed to BACKOFF.
			name:      "Snapshot/K3sExited absorbed",
			initState: StateSnapshot,
			event:     Event{Type: EvK3sExited},
			wantState: StateSnapshot,
		},
		{
			// k3s is never stopped for the snapshot, so there is no
			// restart to make: go straight to the readiness check.
			name:      "Snapshot/SnapshotDone->WaitK3sReady and sets PhaseSteady",
			initState: StateSnapshot,
			initPhase: PhaseFirstBoot,
			event:     Event{Type: EvSnapshotDone},
			wantState: StateWaitK3sReady,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseSteady {
					t.Errorf("phase = %v, want PhaseSteady so it skips DEPLOYING", d.phase)
				}
			},
		},

		// === RUNNING ===
		{
			name:      "Running/K3sExited->Backoff and increments restartCount",
			initState: StateRunning,
			event:     Event{Type: EvK3sExited, Err: errors.New("crashed")},
			wantState: StateBackoff,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartCount != 1 {
					t.Errorf("restartCount = %d, want 1", d.restartCount)
				}
			},
		},
		{
			name:      "Running/SocketRestart->StoppingK3s with restartSocket",
			initState: StateRunning,
			event:     Event{Type: EvSocketRestart},
			wantState: StateStoppingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartSocket {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			name:      "Running/SIGHUP->StoppingK3s with restartSIGHUP",
			initState: StateRunning,
			event:     Event{Type: EvSIGHUP},
			wantState: StateStoppingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartSIGHUP {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			name:      "Running/ConfigChange->StoppingK3s with restartConfigChange",
			initState: StateRunning,
			event:     Event{Type: EvConfigChange},
			wantState: StateStoppingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartConfigChange {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			name:      "Running/ClusterRecycle->StoppingK3s with restartFullRecycle",
			initState: StateRunning,
			event:     Event{Type: EvClusterRecycle},
			wantState: StateStoppingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartFullRecycle {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			name:      "Running/HealthTick keeps Running (no monitor)",
			initState: StateRunning,
			event:     Event{Type: EvHealthTick},
			wantState: StateRunning,
		},
		{
			name:      "Running/Error keeps Running (non-fatal)",
			initState: StateRunning,
			event:     Event{Type: EvError, Err: errors.New("minor")},
			wantState: StateRunning,
		},

		// === BACKOFF ===
		{
			name:      "Backoff/BackoffExpired->StartingK3s with PhaseSteady",
			initState: StateBackoff,
			event:     Event{Type: EvBackoffExpired},
			wantState: StateStartingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseSteady {
					t.Errorf("phase = %v", d.phase)
				}
			},
		},
		{
			name:      "Backoff/SocketRestart->RunningHooks (skip stop, k3s is dead)",
			initState: StateBackoff,
			event:     Event{Type: EvSocketRestart},
			wantState: StateRunningHooks,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartSocket {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			name:      "Backoff/SIGHUP->RunningHooks",
			initState: StateBackoff,
			event:     Event{Type: EvSIGHUP},
			wantState: StateRunningHooks,
		},
		{
			name:      "Backoff/ConfigChange->RunningHooks",
			initState: StateBackoff,
			event:     Event{Type: EvConfigChange},
			wantState: StateRunningHooks,
		},
		{
			name:      "Backoff/ClusterRecycle->RunningHooks with PhaseRecycle",
			initState: StateBackoff,
			event:     Event{Type: EvClusterRecycle},
			wantState: StateRunningHooks,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseRecycle {
					t.Errorf("phase = %v", d.phase)
				}
				if d.restartReason != restartFullRecycle {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			name:      "Backoff/K3sExited absorbed",
			initState: StateBackoff,
			event:     Event{Type: EvK3sExited},
			wantState: StateBackoff,
		},
		{
			name:      "Backoff/Error stays in Backoff",
			initState: StateBackoff,
			event:     Event{Type: EvError, Err: errors.New("x")},
			wantState: StateBackoff,
		},

		// === STOPPING_K3S ===
		{
			name:       "StoppingK3s/StopDone+FullRecycle->RunningHooks (PhaseRecycle)",
			initState:  StateStoppingK3s,
			initReason: restartFullRecycle,
			event:      Event{Type: EvStopDone},
			wantState:  StateRunningHooks,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseRecycle {
					t.Errorf("phase = %v", d.phase)
				}
			},
		},
		{
			name:       "StoppingK3s/StopDone+Socket->RunningHooks",
			initState:  StateStoppingK3s,
			initReason: restartSocket,
			event:      Event{Type: EvStopDone},
			wantState:  StateRunningHooks,
		},
		{
			name:       "StoppingK3s/StopDone+Crash->StartingK3s (no hooks)",
			initState:  StateStoppingK3s,
			initReason: restartCrash,
			event:      Event{Type: EvStopDone},
			wantState:  StateStartingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseSteady {
					t.Errorf("phase = %v", d.phase)
				}
			},
		},
		{
			name:      "StoppingK3s/K3sExited absorbed",
			initState: StateStoppingK3s,
			event:     Event{Type: EvK3sExited},
			wantState: StateStoppingK3s,
		},
		{
			name:      "StoppingK3s/SocketRestart queues",
			initState: StateStoppingK3s,
			event:     Event{Type: EvSocketRestart},
			wantState: StateStoppingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil {
					t.Error("expected pending restart")
				}
			},
		},

		// === RUNNING_HOOKS ===
		{
			name:       "RunningHooks/HooksDone+FullRecycle->Configuring",
			initState:  StateRunningHooks,
			initReason: restartFullRecycle,
			event:      Event{Type: EvHooksDone},
			wantState:  StateConfiguring,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseRecycle {
					t.Errorf("phase = %v", d.phase)
				}
			},
		},
		{
			name:       "RunningHooks/HooksDone+Socket->StartingK3s",
			initState:  StateRunningHooks,
			initReason: restartSocket,
			event:      Event{Type: EvHooksDone},
			wantState:  StateStartingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseSteady {
					t.Errorf("phase = %v", d.phase)
				}
			},
		},
		{
			// Hook failures must not strand the daemon: a
			// misconfigured operator hook would otherwise lock
			// the device in BACKOFF until manual intervention.
			name:      "RunningHooks/Error proceeds to StartingK3s",
			initState: StateRunningHooks,
			event:     Event{Type: EvError, Err: errors.New("hook failed")},
			wantState: StateStartingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseSteady {
					t.Errorf("phase = %v", d.phase)
				}
			},
		},
		{
			name:      "RunningHooks/SocketRestart queues",
			initState: StateRunningHooks,
			event:     Event{Type: EvSocketRestart},
			wantState: StateRunningHooks,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil {
					t.Error("expected pending restart")
				}
			},
		},

		// === CLUSTER_TRANSITION entry ===
		{
			name:      "Running/SingleToCluster->ClusterTransition (no Stop/Hooks)",
			initState: StateRunning,
			event:     Event{Type: EvSingleToCluster},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartSingleToCluster {
					t.Errorf("restartReason = %d", d.restartReason)
				}
				if d.backoff != minBackoff {
					t.Errorf("backoff = %v, want minBackoff", d.backoff)
				}
			},
		},
		{
			name:      "Running/ClusterToSingle->ClusterTransition",
			initState: StateRunning,
			event:     Event{Type: EvClusterToSingle},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.restartReason != restartClusterToSingle {
					t.Errorf("restartReason = %d", d.restartReason)
				}
			},
		},
		{
			// Sampled from a state as far from RUNNING as the FSM
			// gets, to pin that the interception is state-independent
			// rather than a list of states someone remembered.
			name:      "Backoff/ClusterToSingle->ClusterTransition",
			initState: StateBackoff,
			event:     Event{Type: EvClusterToSingle},
			wantState: StateClusterTransition,
		},
		{
			// The one exception: a transition already in flight is
			// not re-entered, the request is queued behind it.
			name:      "ClusterTransition/ClusterToSingle queues, no re-entry",
			initState: StateClusterTransition,
			event:     Event{Type: EvClusterToSingle},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil {
					t.Fatal("expected pending restart")
				}
				if *d.pendingRestart != restartClusterToSingle {
					t.Errorf("pendingRestart = %v, want restartClusterToSingle",
						restartReasonString(*d.pendingRestart))
				}
			},
		},

		// === CLUSTER_TRANSITION exit ===
		{
			name:      "ClusterTransition/TransitionDone->StartingK3s (PhaseRecycle, restartCount reset)",
			initState: StateClusterTransition,
			event:     Event{Type: EvTransitionDone},
			wantState: StateStartingK3s,
			checkFn: func(t *testing.T, d *daemon) {
				if d.phase != PhaseRecycle {
					t.Errorf("phase = %v", d.phase)
				}
				if d.restartCount != 0 {
					t.Errorf("restartCount = %d, want 0", d.restartCount)
				}
			},
		},
		{
			// Must STAY in CLUSTER_TRANSITION and retry. Leaving for
			// any other state skips the steps after the failed one —
			// clear-tls-if-join among them — while the cluster-mode
			// marker is already set, so the next state starts k3s in
			// join mode against the single-node CA and crash-loops
			// forever. Observed 2026-08-02: a transient CRD race in
			// multus-reset bricked a node this way.
			name:      "ClusterTransition/Error retries, never falls through",
			initState: StateClusterTransition,
			event:     Event{Type: EvError, Err: errors.New("step failed")},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.lastError == nil {
					t.Error("lastError should be set")
				}
				if d.transitionStep != "" {
					t.Errorf("transitionStep = %q, want cleared before retry",
						d.transitionStep)
				}
			},
		},
		{
			name:      "ClusterTransition/K3sExited absorbed",
			initState: StateClusterTransition,
			event:     Event{Type: EvK3sExited, Err: errors.New("k3s gone")},
			wantState: StateClusterTransition,
		},
		{
			name:      "ClusterTransition/SocketRestart queued",
			initState: StateClusterTransition,
			event:     Event{Type: EvSocketRestart},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil || *d.pendingRestart != restartSocket {
					t.Errorf("pendingRestart = %v", d.pendingRestart)
				}
			},
		},
		{
			name:      "ClusterTransition/SingleToCluster queued (do not interrupt)",
			initState: StateClusterTransition,
			event:     Event{Type: EvSingleToCluster},
			wantState: StateClusterTransition,
			checkFn: func(t *testing.T, d *daemon) {
				if d.pendingRestart == nil ||
					*d.pendingRestart != restartSingleToCluster {
					t.Errorf("pendingRestart = %v", d.pendingRestart)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDaemon()
			d.state = tt.initState
			d.phase = tt.initPhase
			d.restartReason = tt.initReason

			d.handleEvent(ctx, tt.event)

			if d.state != tt.wantState {
				t.Errorf("state = %v, want %v", d.state, tt.wantState)
			}
			if tt.checkFn != nil {
				tt.checkFn(t, d)
			}
		})
	}
}

// TestGlobalSIGTERM checks that EvSIGTERM moves us to ShuttingDown
// from every state. This is the contract that the kube container's
// SIGTERM on stop reliably terminates the daemon regardless of what
// it was doing.
func TestGlobalSIGTERM(t *testing.T) {
	allStates := []State{
		StateInit, StateInstalling, StateStartingCtrd, StateConfiguring,
		StateStartingK3s, StateImporting, StateWaitK3sReady, StateDeploying,
		StateSnapshot, StateRunning, StateBackoff, StateStoppingK3s,
		StateRunningHooks, StateClusterTransition,
	}
	ctx := context.Background()
	for _, s := range allStates {
		t.Run(s.String(), func(t *testing.T) {
			d := newTestDaemon()
			d.state = s
			d.handleEvent(ctx, Event{Type: EvSIGTERM})
			if d.state != StateShuttingDown {
				t.Errorf("after EvSIGTERM in %v: state = %v", s, d.state)
			}
		})
	}
}

// TestGlobalSocketStop mirrors the SIGTERM contract for the
// control socket's "stop" command.
func TestGlobalSocketStop(t *testing.T) {
	allStates := []State{
		StateInit, StateInstalling, StateStartingCtrd, StateConfiguring,
		StateStartingK3s, StateImporting, StateWaitK3sReady, StateDeploying,
		StateSnapshot, StateRunning, StateBackoff, StateStoppingK3s,
		StateRunningHooks, StateClusterTransition,
	}
	ctx := context.Background()
	for _, s := range allStates {
		t.Run(s.String(), func(t *testing.T) {
			d := newTestDaemon()
			d.state = s
			d.handleEvent(ctx, Event{Type: EvSocketStop})
			if d.state != StateShuttingDown {
				t.Errorf("after EvSocketStop in %v: state = %v", s, d.state)
			}
		})
	}
}

// TestSocketStatus pins the contract that EvSocketStatus is a
// read-only probe: it must reply on the channel and must not
// change the FSM state.
func TestSocketStatus(t *testing.T) {
	ctx := context.Background()
	d := newTestDaemon()
	d.state = StateRunning
	d.phase = PhaseSteady

	reply := make(chan string, 1)
	d.handleEvent(ctx, Event{Type: EvSocketStatus, Reply: reply})

	if d.state != StateRunning {
		t.Errorf("state changed to %v", d.state)
	}
	select {
	case msg := <-reply:
		if msg == "" {
			t.Error("expected non-empty status reply")
		}
	default:
		t.Error("no reply received")
	}
}

// TestQueueRestartPriority verifies that the queue keeps the
// highest-priority pending reason. A cluster recycle observed
// during a SIGHUP-driven restart cycle must not be lost — the
// FSM is supposed to drain to the recycle, not the SIGHUP.
func TestQueueRestartPriority(t *testing.T) {
	d := newTestDaemon()

	d.queueRestart(restartSocket)
	if d.pendingRestart == nil || *d.pendingRestart != restartSocket {
		t.Fatal("expected restartSocket queued")
	}

	d.queueRestart(restartFullRecycle)
	if *d.pendingRestart != restartFullRecycle {
		t.Errorf("pending = %d, want restartFullRecycle", *d.pendingRestart)
	}

	d.queueRestart(restartSIGHUP)
	if *d.pendingRestart != restartFullRecycle {
		t.Errorf("pending = %d, want restartFullRecycle after lower-priority enqueue",
			*d.pendingRestart)
	}
}

// TestNeedsHooks pins the "crash skips hooks" contract. Hooks are
// operator-defined; running them against an already-dead k3s adds
// latency and can fail noisily on a hot-loop crash recovery, so
// crash recovery deliberately bypasses them.
func TestNeedsHooks(t *testing.T) {
	if needsHooks(restartCrash) {
		t.Error("crash should not need hooks")
	}
	for _, r := range []restartReason{
		restartSocket, restartSIGHUP,
		restartConfigChange, restartFullRecycle,
	} {
		if !needsHooks(r) {
			t.Errorf("reason %d should need hooks", r)
		}
	}
}

// TestHandleInitCopiesResult pins the publish-once contract for
// initResult: after EvPrereqsDone the daemon must have copied
// every field and cleared the pointer, so a later spurious
// EvPrereqsDone cannot revive stale data.
func TestHandleInitCopiesResult(t *testing.T) {
	ctx := context.Background()
	d := newTestDaemon()
	d.state = StateInit
	d.initRes = &initResult{
		deviceName:      "test-device",
		uuid:            "test-uuid",
		eveRelease:      "0.0.0-test",
		installKubevirt: true,
		phase:           PhaseSteady,
	}

	d.handleEvent(ctx, Event{Type: EvPrereqsDone})

	if d.deviceName != "test-device" {
		t.Errorf("deviceName = %q", d.deviceName)
	}
	if d.uuid != "test-uuid" {
		t.Errorf("uuid = %q", d.uuid)
	}
	if d.eveRelease != "0.0.0-test" {
		t.Errorf("eveRelease = %q", d.eveRelease)
	}
	if !d.installKubevirt {
		t.Error("installKubevirt = false")
	}
	if d.phase != PhaseSteady {
		t.Errorf("phase = %v", d.phase)
	}
	if d.initRes != nil {
		t.Error("initRes should be nil after consumption")
	}
}

// TestEvRetryCallsEnterState confirms EvRetry triggers a re-entry
// of the current state via enterStateFn rather than a transition.
// This is what makes the retry-on-error pattern idempotent — a
// state can be re-entered without first transitioning out.
func TestEvRetryCallsEnterState(t *testing.T) {
	ctx := context.Background()
	d := newTestDaemon()
	d.state = StateConfiguring

	called := false
	d.enterStateFn = func(context.Context) { called = true }

	d.handleEvent(ctx, Event{Type: EvRetry})

	if !called {
		t.Error("enterStateFn was not called on EvRetry")
	}
	if d.state != StateConfiguring {
		t.Errorf("state changed to %v", d.state)
	}
}

// TestComputeBackoff covers the four branches of the backoff
// arithmetic that drive crash recovery cadence:
//
//   - stable run (k3sStartedAt > stableThreshold ago) → reset to
//     minBackoff regardless of current backoff;
//   - unstable run → double up to maxBackoff;
//   - cap saturates at maxBackoff (next double does not exceed);
//   - k3sStartedAt zero (never set) → treated as unstable.
//
// A regression on any of these silently changes the recovery
// pacing — there is no log line that says "this should have
// reset", so the FSM table tests alone would not catch it.
func TestComputeBackoff(t *testing.T) {
	cases := []struct {
		name         string
		startedDelta time.Duration // sub from now; 0 = zero time
		initBackoff  time.Duration
		wantBackoff  time.Duration
	}{
		{
			name:         "stable run resets to minBackoff",
			startedDelta: 5 * time.Minute,
			initBackoff:  4 * time.Minute,
			wantBackoff:  minBackoff,
		},
		{
			name:         "unstable run doubles",
			startedDelta: 1 * time.Second,
			initBackoff:  10 * time.Second,
			wantBackoff:  20 * time.Second,
		},
		{
			name:         "double saturates at maxBackoff",
			startedDelta: 1 * time.Second,
			initBackoff:  4 * time.Minute,
			wantBackoff:  maxBackoff,
		},
		{
			name:         "already at maxBackoff stays",
			startedDelta: 1 * time.Second,
			initBackoff:  maxBackoff,
			wantBackoff:  maxBackoff,
		},
		{
			name:         "zero k3sStartedAt treated as unstable",
			startedDelta: 0,
			initBackoff:  10 * time.Second,
			wantBackoff:  20 * time.Second,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newTestDaemon()
			d.backoff = c.initBackoff
			if c.startedDelta > 0 {
				d.k3sStartedAt = time.Now().Add(-c.startedDelta)
			}
			d.computeBackoff()
			if d.backoff != c.wantBackoff {
				t.Errorf("backoff = %v, want %v", d.backoff, c.wantBackoff)
			}
		})
	}
}

// TestProcessPendingRestart pins the queue/drain symmetry: each
// reason must drain back to the matching event type, with
// pendingRestart cleared. A reordering of restartReason constants
// without updating processPendingRestart would silently route a
// queued ClusterToSingle into an EvSocketRestart — exactly the
// kind of regression this test catches.
func TestProcessPendingRestart(t *testing.T) {
	cases := []struct {
		reason   restartReason
		wantType EventType
	}{
		{restartSocket, EvSocketRestart},
		{restartSIGHUP, EvSIGHUP},
		{restartConfigChange, EvConfigChange},
		{restartFullRecycle, EvClusterRecycle},
		{restartSingleToCluster, EvSingleToCluster},
		{restartClusterToSingle, EvClusterToSingle},
	}
	for _, c := range cases {
		t.Run(c.wantType.String(), func(t *testing.T) {
			d := newTestDaemon()
			r := c.reason
			d.pendingRestart = &r
			d.processPendingRestart()
			if d.pendingRestart != nil {
				t.Errorf("pendingRestart not cleared: %v", *d.pendingRestart)
			}
			// processPendingRestart now sends from a goroutine to
			// avoid blocking the run loop. Wait briefly for the
			// send.
			select {
			case ev := <-d.eventCh:
				if ev.Type != c.wantType {
					t.Errorf("got %s, want %s", ev.Type, c.wantType)
				}
			case <-time.After(time.Second):
				t.Fatalf("no event posted for reason %d", c.reason)
			}
		})
	}
}

// TestBridgeMonitorRestartsMapping covers the explicit per-reason
// mapping plus the unknown-reason fallback. The fallback is the
// safety net so a future monitor.RestartReason added without
// updating this switch still triggers a config-reload restart
// rather than dropping the signal.
func TestBridgeMonitorRestartsMapping(t *testing.T) {
	cases := []struct {
		name     string
		reason   monitor.RestartReason
		wantType EventType
	}{
		{"FullRecycle", monitor.RestartFullRecycle, EvClusterRecycle},
		{"ConfigChange", monitor.RestartConfigChange, EvConfigChange},
		{"SingleToCluster", monitor.RestartSingleToCluster, EvSingleToCluster},
		{"ClusterToSingle", monitor.RestartClusterToSingle, EvClusterToSingle},
		{"Unknown falls back to ConfigChange", monitor.RestartReason(999), EvConfigChange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newTestDaemon()
			d.bridgeOneMonitorRestart(c.reason)
			select {
			case ev := <-d.eventCh:
				if ev.Type != c.wantType {
					t.Errorf("got %s, want %s", ev.Type, c.wantType)
				}
			default:
				t.Fatal("no event posted")
			}
		})
	}
}

// TestRestartReasonMonitorAlignment pins the numeric equality
// between restartReason 3..6 and monitor.Restart* — the comment
// in main.go relies on this for human readability and a parity
// test catches any future drift on either side.
func TestRestartReasonMonitorAlignment(t *testing.T) {
	pairs := []struct {
		name string
		a    restartReason
		b    monitor.RestartReason
	}{
		{"ConfigChange", restartConfigChange, monitor.RestartConfigChange},
		{"FullRecycle", restartFullRecycle, monitor.RestartFullRecycle},
		{"SingleToCluster", restartSingleToCluster, monitor.RestartSingleToCluster},
		{"ClusterToSingle", restartClusterToSingle, monitor.RestartClusterToSingle},
	}
	for _, p := range pairs {
		if int(p.a) != int(p.b) {
			t.Errorf("%s: restartReason=%d monitor=%d (alignment broken)",
				p.name, int(p.a), int(p.b))
		}
	}
}

// TestStatusStringConditionalShape covers the non-obvious branches
// of the status socket reply: the k3s=dead / k3s=stopping /
// k3s=not-started tokens that external watchers read to
// distinguish recovery from a never-started daemon, and the
// transition-step=… token that only appears during a
// CLUSTER_TRANSITION with a non-empty step.
func TestStatusStringConditionalShape(t *testing.T) {
	cases := []struct {
		name           string
		setup          func(*daemon)
		wantContains   []string
		wantNotContain []string
	}{
		{
			name: "Backoff reports k3s=dead",
			setup: func(d *daemon) {
				d.state = StateBackoff
			},
			wantContains: []string{"state=BACKOFF", "k3s=dead"},
		},
		{
			name: "StoppingK3s reports k3s=stopping",
			setup: func(d *daemon) {
				d.state = StateStoppingK3s
			},
			wantContains: []string{"state=STOPPING_K3S", "k3s=stopping"},
		},
		{
			name: "Init reports k3s=not-started",
			setup: func(d *daemon) {
				d.state = StateInit
			},
			wantContains: []string{"state=INIT", "k3s=not-started"},
		},
		{
			name: "ClusterTransition with step exposes transition-step",
			setup: func(d *daemon) {
				d.state = StateClusterTransition
				d.setTransitionStep("rotate-token")
			},
			wantContains: []string{
				"state=CLUSTER_TRANSITION",
				"transition-step=rotate-token",
			},
		},
		{
			name: "ClusterTransition with empty step omits the field",
			setup: func(d *daemon) {
				d.state = StateClusterTransition
			},
			wantContains:   []string{"state=CLUSTER_TRANSITION"},
			wantNotContain: []string{"transition-step="},
		},
		{
			name: "lastError surfaces when set",
			setup: func(d *daemon) {
				d.state = StateRunning
				d.lastError = errors.New("boom")
			},
			wantContains: []string{`last-error="boom"`},
		},
		{
			name: "pendingRestart surfaces when set",
			setup: func(d *daemon) {
				d.state = StateBackoff
				r := restartFullRecycle
				d.pendingRestart = &r
			},
			wantContains: []string{"pending-restart=full-recycle"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newTestDaemon()
			c.setup(d)
			got := d.statusString()
			for _, want := range c.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("got %q, missing %q", got, want)
				}
			}
			for _, notWant := range c.wantNotContain {
				if strings.Contains(got, notWant) {
					t.Errorf("got %q, should not contain %q", got, notWant)
				}
			}
		})
	}
}

// TestGraphReport covers the live overlay k3s-sctl prints: a signal edge
// must say whether its condition holds, and a component gated by an
// unmet condition must be named along with what it waits on. Without
// that an operator only learns a component has not run, not why.
func TestGraphReport(t *testing.T) {
	edges := []deploy.Edge{
		{From: "namespace", To: "multus", Rule: "signal",
			Signal: deploy.EveKubeAppNamespaceExists},
		{From: "multus", To: "cdi-operator", Rule: "signal",
			Signal: deploy.MultusCNIReady},
		{From: "cdi-operator", To: "cdi", Rule: "signal",
			Signal: deploy.CDIOperatorReady},
		{From: "manifests", To: "longhorn", Rule: "policy"},
	}

	bus := deploy.NewBus()
	bus.Emit(deploy.EveKubeAppNamespaceExists)
	bus.Emit(deploy.MultusCNIReady)

	got := graphReport(edges, bus)

	for _, want := range []string{
		"signal EveKubeAppNamespaceExists [met]",
		"signal MultusCNIReady [met]",
		"signal CDIOperatorReady [WAITING]",
		"blocked: cdi(CDIOperatorReady)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q\n--- got ---\n%s", want, got)
		}
	}
	// A policy edge has no condition to report.
	if strings.Contains(got, "manifests → longhorn  signal") {
		t.Errorf("policy edge reported as a signal\n%s", got)
	}
	// cdi-operator's own gate is met, so it must not appear as blocked.
	if strings.Contains(got, "cdi-operator(") {
		t.Errorf("cdi-operator reported blocked though MultusCNIReady is met\n%s", got)
	}
}

func TestGraphReportEmptyAndNilBus(t *testing.T) {
	if got := graphReport(nil, nil); !strings.Contains(got, "no dependency edges") {
		t.Errorf("empty graph: got %q", got)
	}
	// A nil bus must read as nothing met rather than panic.
	edges := []deploy.Edge{
		{From: "a", To: "b", Rule: "signal", Signal: deploy.MultusCNIReady},
	}
	got := graphReport(edges, nil)
	if !strings.Contains(got, "[WAITING]") || !strings.Contains(got, "blocked: b(MultusCNIReady)") {
		t.Errorf("nil bus: got %q", got)
	}
}

// TestJoinStageRankOnlyCountsForwardProgress pins what "progress" means
// for the join watchdog. A crash-looping node cycles
// STARTING_K3S → WAIT_K3S_READY → BACKOFF forever; if any of that read
// as progress the watchdog would never fire on the failure it exists
// for. Equally, a slow join that keeps advancing must keep kicking it.
func TestJoinStageRankOnlyCountsForwardProgress(t *testing.T) {
	forward := []State{
		StateStartingK3s, StateImporting, StateWaitK3sReady,
		StateDeploying, StateSnapshot, StateRunning,
	}
	last := 0
	for _, s := range forward {
		r := joinStageRank(s)
		if r <= last {
			t.Errorf("joinStageRank(%v) = %d, want > %d — the join path must be strictly ordered",
				s, r, last)
		}
		last = r
	}

	for _, s := range []State{
		StateBackoff, StateStoppingK3s, StateRunningHooks,
		StateClusterTransition, StateInit, StateInstalling,
		StateStartingCtrd, StateConfiguring, StateShuttingDown,
	} {
		if r := joinStageRank(s); r != 0 {
			t.Errorf("joinStageRank(%v) = %d, want 0 — revisiting this is not progress", s, r)
		}
	}
}

// TestNoteJoinProgressIgnoresRepeats: the crash loop in full. Only the
// first arrival at each stage advances; going round again does not.
func TestNoteJoinProgressIgnoresRepeats(t *testing.T) {
	d := newTestDaemon()

	d.noteJoinProgress(StateStartingK3s)
	d.noteJoinProgress(StateWaitK3sReady)
	peak := d.joinStageReached

	// ... and now it crash-loops.
	for range 3 {
		d.noteJoinProgress(StateBackoff)
		d.noteJoinProgress(StateStartingK3s)
		d.noteJoinProgress(StateWaitK3sReady)
	}
	if d.joinStageReached != peak {
		t.Errorf("joinStageReached = %d after a crash loop, want %d unchanged",
			d.joinStageReached, peak)
	}

	// Reaching RUNNING is completion and resets the episode.
	d.noteJoinProgress(StateRunning)
	if d.joinStageReached != 0 {
		t.Errorf("joinStageReached = %d after RUNNING, want 0", d.joinStageReached)
	}
}

// TestJoinStageResetsWhenATransitionCompletes is the edge-dev2 bug.
// joinStageReached is a high-water mark, and first boot climbs it to
// SNAPSHOT before any transition runs. If it is not cleared when the
// join starts, every stage of that join (STARTING_K3S, IMPORTING,
// WAIT_K3S_READY) ranks below the mark, records no progress at all, and
// the watchdog reboots a healthy node the moment the stall limit
// expires — which it did, twice, on 2026-08-02.
func TestJoinStageResetsWhenATransitionCompletes(t *testing.T) {
	ctx := context.Background()
	d := newTestDaemon()

	// First boot climbs to SNAPSHOT.
	for _, s := range []State{
		StateStartingK3s, StateImporting, StateWaitK3sReady,
		StateDeploying, StateSnapshot,
	} {
		d.noteJoinProgress(s)
	}
	if d.joinStageReached != joinStageRank(StateSnapshot) {
		t.Fatalf("precondition: joinStageReached = %d, want %d",
			d.joinStageReached, joinStageRank(StateSnapshot))
	}

	// The transition finishes and hands off to STARTING_K3S.
	d.state = StateClusterTransition
	d.restartReason = restartSingleToCluster
	d.handleEvent(ctx, Event{Type: EvTransitionDone})

	// The handler clears the mark and then transitions to
	// STARTING_K3S, which immediately re-records rank 1. What matters
	// is that the mark came DOWN from SNAPSHOT: without the reset it
	// would still read 5 and nothing in the join could ever exceed it.
	if got, want := d.joinStageReached, joinStageRank(StateStartingK3s); got != want {
		t.Fatalf("joinStageReached = %d after EvTransitionDone, want %d "+
			"(reset, then STARTING_K3S recorded)", got, want)
	}
	if d.joinStageReached >= joinStageRank(StateSnapshot) {
		t.Fatalf("joinStageReached = %d still at or above the first-boot "+
			"high-water mark %d — the join would record no progress at all",
			d.joinStageReached, joinStageRank(StateSnapshot))
	}

	// And the rest of the join's stages keep counting.
	d.noteJoinProgress(StateWaitK3sReady)
	if d.joinStageReached != joinStageRank(StateWaitK3sReady) {
		t.Errorf("joinStageReached = %d, want %d", d.joinStageReached,
			joinStageRank(StateWaitK3sReady))
	}
}
