// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package main implements kube-init — the daemon that brings up k3s
// inside the EVE kube linuxkit container and supervises it.
//
// The daemon is structured as a finite state machine. State entry
// actions launch background work that posts a completion event
// back to a single event channel; the main loop dispatches on that
// channel and never blocks. The control socket
// (/run/k3s-supervisor.sock) accepts status/restart/stop requests
// from the moment the daemon starts, including during long
// first-boot install passes.
//
// Happy path (first boot):
//
//	INIT → INSTALLING → STARTING_CTRD → CONFIGURING → STARTING_K3S
//	     → IMPORTING → WAIT_K3S_READY → DEPLOYING → RUNNING
//
// Lifecycle branches:
//
//	BACKOFF              — exponential wait after k3s exit
//	STOPPING_K3S         — graceful k3s shutdown in progress
//	RUNNING_HOOKS        — operator-defined pre-restart scripts
//	CLUSTER_TRANSITION   — single↔HA mode flip runner
//	SHUTTING_DOWN        — clean daemon exit
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/lf-edge/eve/pkg/kube/kube-init/clustermode"
	"github.com/lf-edge/eve/pkg/kube/kube-init/components"
	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/images"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeconfig"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/mgmtproxy"
	"github.com/lf-edge/eve/pkg/kube/kube-init/monitor"
	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/prereqs"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/kube/kube-init/update"
)

// ===========================================================================
// Events
// ===========================================================================

// EventType identifies which transition signal arrived.
type EventType int

// Event-type values. Each constant's trailing comment documents
// the signal that produces the event; the FSM dispatches on these
// in handleEvent. Order is significant only insofar as String()'s
// switch lists them in the same order — see String().
const (
	EvTick            EventType = iota // reserved heartbeat
	EvPrereqsDone                      // prereqs.RunAll finished
	EvInstallDone                      // k3s.EnsureInstalled finished
	EvContainerdReady                  // containerd socket appeared
	EvConfigureDone                    // k3s.Configure + CNI staging finished
	EvK3sStarted                       // kubeconfig appeared after k3s fork
	EvImagesDone                       // images.ImportAll finished
	EvK3sReady                         // k3s node reports Ready
	EvDeployDone                       // components.DeployAll + markers finished
	EvK3sExited                        // supervisor.Done fired
	EvStopDone                         // supervisor.Stop finished, ports freed
	EvHooksDone                        // supervisor.RunHooks finished
	EvBackoffExpired                   // backoff timer fired
	EvSocketRestart                    // control socket "restart"
	EvSocketStatus                     // control socket "status"
	EvSocketStop                       // control socket "stop"
	EvSIGHUP                           // OS SIGHUP
	EvSIGTERM                          // OS SIGTERM / SIGINT
	EvConfigChange                     // monitor: user override changed
	EvClusterRecycle                   // monitor: generic recycle
	EvHealthTick                       // health-check timer fired
	EvHealthDone                       // health-check worker finished
	EvSingleToCluster                  // monitor: ENC appeared
	EvClusterToSingle                  // monitor: ENC removed
	EvTransitionDone                   // clustermode runner finished
	EvError                            // async work returned err
	EvRetry                            // re-enter current state after a delay
)

// String renders EventType for logging. Uses an explicit switch
// rather than a slice-index lookup so a reordered iota cannot
// silently produce wrong log lines — every constant is named
// directly and the compiler flags a rename.
func (e EventType) String() string {
	switch e {
	case EvTick:
		return "EvTick"
	case EvPrereqsDone:
		return "EvPrereqsDone"
	case EvInstallDone:
		return "EvInstallDone"
	case EvContainerdReady:
		return "EvContainerdReady"
	case EvConfigureDone:
		return "EvConfigureDone"
	case EvK3sStarted:
		return "EvK3sStarted"
	case EvImagesDone:
		return "EvImagesDone"
	case EvK3sReady:
		return "EvK3sReady"
	case EvDeployDone:
		return "EvDeployDone"
	case EvK3sExited:
		return "EvK3sExited"
	case EvStopDone:
		return "EvStopDone"
	case EvHooksDone:
		return "EvHooksDone"
	case EvBackoffExpired:
		return "EvBackoffExpired"
	case EvSocketRestart:
		return "EvSocketRestart"
	case EvSocketStatus:
		return "EvSocketStatus"
	case EvSocketStop:
		return "EvSocketStop"
	case EvSIGHUP:
		return "EvSIGHUP"
	case EvSIGTERM:
		return "EvSIGTERM"
	case EvConfigChange:
		return "EvConfigChange"
	case EvClusterRecycle:
		return "EvClusterRecycle"
	case EvHealthTick:
		return "EvHealthTick"
	case EvHealthDone:
		return "EvHealthDone"
	case EvSingleToCluster:
		return "EvSingleToCluster"
	case EvClusterToSingle:
		return "EvClusterToSingle"
	case EvTransitionDone:
		return "EvTransitionDone"
	case EvError:
		return "EvError"
	case EvRetry:
		return "EvRetry"
	}
	return fmt.Sprintf("EvUnknown(%d)", e)
}

// Event carries a typed notification through the FSM's event channel.
type Event struct {
	Type   EventType
	Err    error       // EvError, EvK3sExited
	Reply  chan string // EvSocketStatus response channel
	Detail string      // optional informational payload (logged via %s)
}

// initResult carries values computed by the StateInit goroutine
// back to handleInit. The startAsync channel synchronisation
// happens-after the worker writes initResult, so handleInit sees
// the fully-published struct.
type initResult struct {
	deviceName      string
	uuid            string
	eveRelease      string
	installKubevirt bool
	phase           Phase
}

// ===========================================================================
// States
// ===========================================================================

// State enumerates the FSM positions.
type State int

// FSM state values. Each constant's trailing comment summarises
// the entry action launched in enterState. String() must list
// every value in the same order.
const (
	StateInit              State = iota // run system prerequisites
	StateInstalling                     // download / unpack k3s
	StateStartingCtrd                   // start user containerd, wait for socket
	StateConfiguring                    // write k3s config drop-ins
	StateStartingK3s                    // launch k3s, wait for kubeconfig
	StateImporting                      // import container images
	StateWaitK3sReady                   // wait for node Ready
	StateDeploying                      // deploy cluster components
	StateRunning                        // steady-state supervision
	StateBackoff                        // exponential wait after exit
	StateStoppingK3s                    // graceful supervisor.Stop
	StateRunningHooks                   // pre-restart hooks
	StateClusterTransition              // single↔HA runner
	StateShuttingDown                   // clean daemon exit
)

// String renders State for logging. Switch-based for the same
// reason as EventType.String: an iota reorder must not silently
// produce wrong log lines.
func (s State) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateInstalling:
		return "INSTALLING"
	case StateStartingCtrd:
		return "STARTING_CTRD"
	case StateConfiguring:
		return "CONFIGURING"
	case StateStartingK3s:
		return "STARTING_K3S"
	case StateImporting:
		return "IMPORTING"
	case StateWaitK3sReady:
		return "WAIT_K3S_READY"
	case StateDeploying:
		return "DEPLOYING"
	case StateRunning:
		return "RUNNING"
	case StateBackoff:
		return "BACKOFF"
	case StateStoppingK3s:
		return "STOPPING_K3S"
	case StateRunningHooks:
		return "RUNNING_HOOKS"
	case StateClusterTransition:
		return "CLUSTER_TRANSITION"
	case StateShuttingDown:
		return "SHUTTING_DOWN"
	}
	return fmt.Sprintf("UNKNOWN(%d)", s)
}

// ===========================================================================
// Phase — controls what follows STARTING_K3S
// ===========================================================================

// Phase tracks which post-start sequence to follow.
type Phase int

// Phase values picked by INIT (from the persisted "initialized"
// marker) and by transitions that need a recycle (cluster mode
// flip, full-recycle restart). The handleStartingK3s switch
// dispatches on this to route post-STARTING_K3S work.
const (
	PhaseFirstBoot Phase = iota // full deploy sequence (fresh device)
	PhaseSteady                 // post-first-boot bring-up; skip DEPLOYING
	PhaseRecycle                // re-configure + re-deploy (cluster-mode flip)
)

func (p Phase) String() string {
	switch p {
	case PhaseFirstBoot:
		return "first-boot"
	case PhaseSteady:
		return "steady"
	case PhaseRecycle:
		return "recycle"
	}
	return fmt.Sprintf("phase(%d)", p)
}

// ===========================================================================
// Restart reasons
// ===========================================================================

// restartReason describes why a k3s restart was requested.
//
// Two invariants live in the numeric values:
//
//   - Numeric ordering encodes priority: queueRestart keeps the
//     highest, so a cluster recycle outranks a SIGHUP outranks a
//     crash. Reordering the constants reorders priority — do not.
//
//   - Values 3..6 happen to match monitor.Restart* by convention,
//     for human readability. The bridge in bridgeMonitorRestarts
//     does an explicit switch; the alignment is NOT load-bearing,
//     but a parity test in main_test.go pins it so a future drift
//     fails CI rather than silently producing the wrong restart
//     reason on the status socket.
//
// Defined type (not alias) so staticcheck flags non-exhaustive
// switches and an int from elsewhere can't be assigned without an
// explicit cast.
type restartReason int

const (
	restartCrash           restartReason = 0
	restartSocket          restartReason = 1
	restartSIGHUP          restartReason = 2
	restartConfigChange    restartReason = 3 // == monitor.RestartConfigChange
	restartFullRecycle     restartReason = 4 // == monitor.RestartFullRecycle
	restartSingleToCluster restartReason = 5 // == monitor.RestartSingleToCluster
	restartClusterToSingle restartReason = 6 // == monitor.RestartClusterToSingle
)

func restartReasonString(r restartReason) string {
	switch r {
	case restartCrash:
		return "crash"
	case restartSocket:
		return "socket-restart"
	case restartSIGHUP:
		return "SIGHUP"
	case restartConfigChange:
		return "config-change"
	case restartFullRecycle:
		return "full-recycle"
	case restartSingleToCluster:
		return "single-to-cluster"
	case restartClusterToSingle:
		return "cluster-to-single"
	}
	return fmt.Sprintf("unknown(%d)", r)
}

// needsHooks reports whether the pre-restart hooks should fire for
// reason. Crash recovery deliberately skips hooks — they would run
// against an already-dead k3s and add latency to backoff recovery.
func needsHooks(r restartReason) bool {
	return r != restartCrash
}

// setTransitionStep / getTransitionStep are the synchronised
// accessors for d.transitionStep. The setter is called from the
// transition worker goroutine via the progress callback; the
// getter is called from statusString on the event loop.
func (d *daemon) setTransitionStep(step string) {
	d.transitionMu.Lock()
	d.transitionStep = step
	d.transitionMu.Unlock()
}

func (d *daemon) getTransitionStep() string {
	d.transitionMu.Lock()
	step := d.transitionStep
	d.transitionMu.Unlock()
	return step
}

// ===========================================================================
// Constants
// ===========================================================================

const (
	minBackoff      = 5 * time.Second
	maxBackoff      = 5 * time.Minute
	stableThreshold = 30 * time.Second // k3s uptime that resets backoff

	healthCheckInterval = 15 * time.Second
	errorRetryDelay     = 5 * time.Second

	kubeconfigTimeout = 10 * time.Minute
	readinessTimeout  = 10 * time.Minute

	socketPath = "/run/k3s-supervisor.sock"
)

// ===========================================================================
// daemon
// ===========================================================================

// daemon holds runtime state for the kube-init process. Field
// access is single-threaded: every read and write happens from the
// run loop goroutine, except for transitionStep (documented below).
type daemon struct {
	// Identity, populated during INIT.
	deviceName      string
	uuid            string
	eveRelease      string
	installKubevirt bool

	// initRes is the work-goroutine's output. The channel send in
	// startAsync happens-after the write, so handleInit sees the
	// published struct after EvPrereqsDone arrives.
	initRes *initResult

	// FSM state.
	state          State
	phase          Phase
	pendingRestart *restartReason // queued restart reason, or nil
	lastError      error          // last error, surfaced via status socket
	restartReason  restartReason  // reason for current stop cycle

	// k3s process.
	supervisor   *k3s.Supervisor
	k3sStartedAt time.Time
	restartCount int
	backoff      time.Duration
	backoffTimer *time.Timer

	// Event bus.
	eventCh chan Event

	// Background workers.
	mon        *monitor.Monitor
	cancelWork context.CancelFunc // cancel current async work goroutine
	cancelExit context.CancelFunc // cancel k3s exit watcher

	// RUNNING-scoped context. Cancelled when leaving RUNNING so
	// bridgeMonitorRestarts and forwardHealthTicks exit promptly
	// instead of leaking until top-level ctx cancellation.
	runningCtx    context.Context
	cancelRunning context.CancelFunc

	// Health check ticker (active only in RUNNING).
	healthTicker *time.Ticker

	// healthInflight gates the health worker: ticks are dropped
	// while a worker is already running so a slow kubectl call
	// cannot back the event channel up.
	healthInflight bool

	// transitionStep names the cluster-mode transition step
	// currently executing (e.g. "rotate-token"). Written by the
	// transition worker goroutine via its progress callback; read
	// only by statusString on the event loop. Strings are
	// (ptr,len) pairs in Go — an unsynchronised read can produce
	// a torn header — so this field is guarded by transitionMu.
	// Access only via setTransitionStep / getTransitionStep.
	transitionMu   sync.Mutex
	transitionStep string

	monRestartCh chan monitor.RestartReason

	// psMgr is the shared pubsub subscription manager. Subscribers
	// across kube-init packages register topics on it before the
	// run loop is started in main.
	psMgr *pubsubclient.Manager

	// enterStateFn is the state-entry dispatcher. Defaults to
	// d.enterState; tests replace it with a no-op to isolate the
	// transition graph from real work.
	enterStateFn func(context.Context)
}

// ===========================================================================
// main
// ===========================================================================

func main() {
	// Tee logs to stderr (container log collector) and a rotated
	// file under /persist so logs survive container restart.
	if err := os.MkdirAll("/persist/kubelog", 0755); err != nil {
		log.Printf("kube-init: mkdir /persist/kubelog: %v", err)
	}
	lj := &lumberjack.Logger{
		Filename:   "/persist/kubelog/k3s-install.log",
		MaxSize:    5, // MB
		MaxBackups: 3,
		LocalTime:  true,
		Compress:   false,
	}
	log.SetOutput(io.MultiWriter(os.Stderr, lj))
	log.SetPrefix("kube-init: ")
	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("starting kube-init daemon (pid=%d, arch=%s)",
		os.Getpid(), runtime.GOARCH)

	// Construct the pubsub manager. kube-init uses this to
	// subscribe to EdgeNodeClusterStatus / KubeConfig /
	// KubeClusterUpdateStatus / EdgeNodeInfo /
	// EdgeNodeClusterConfig instead of polling the JSON files
	// those topics drop under /run and /persist. The manager
	// pattern (mirroring pkg/pillar/cmd/monitor) lets each
	// subscriber package register its topic+handlers separately,
	// then a single goroutine drives them all through
	// pubsub.MultiChannelWatch. Subscriptions themselves come in
	// follow-up commits; this is the foundation that ensures the
	// pubsub library is reachable from inside the kube container.
	psLogger := logrus.New()
	psLogger.SetOutput(io.MultiWriter(os.Stderr, lj))
	psMgr, err := pubsubclient.New(psLogger)
	if err != nil {
		log.Fatalf("pubsub init: %v", err)
	}
	log.Printf("pubsub manager constructed (agent=%s)", pubsubclient.AgentName)

	// Register all topic subscribers before psMgr.Run starts —
	// the Manager activates registered subscriptions at Run time
	// so the order of registration calls doesn't matter, but
	// every subscriber must be registered first.
	if err := edgenodeinfo.Register(psMgr); err != nil {
		log.Fatalf("register EdgeNodeInfo subscription: %v", err)
	}
	if err := kubeconfig.Register(psMgr); err != nil {
		log.Fatalf("register KubeConfig subscription: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Drive the pubsub event loop on its own goroutine. Returns
	// when ctx is cancelled (signal handler below). The Run loop
	// blocks until then; subscribers see deliveries as soon as
	// pillar has published.
	go func() {
		if err := psMgr.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("pubsub run loop exited unexpectedly: %v", err)
		}
	}()

	d := &daemon{
		installKubevirt: true,
		phase:           PhaseFirstBoot,
		backoff:         minBackoff,
		eventCh:         make(chan Event, 32),
		monRestartCh:    make(chan monitor.RestartReason, 4),
		psMgr:           psMgr,
	}

	initialized, err := state.IsInitialized()
	if err != nil {
		log.Printf("check initialized marker: %v (assuming first boot)", err)
	}
	if initialized {
		log.Printf("previous initialization found")
	} else {
		log.Printf("first boot — full initialization required")
	}
	// Phase is recomputed inside the INIT goroutine after
	// RunAll, where we also handle the convert-to-single-node
	// case. Default to first-boot until then.

	d.enterStateFn = d.enterState
	d.run(ctx)
}

// ===========================================================================
// Main loop
// ===========================================================================

func (d *daemon) run(ctx context.Context) {
	go d.signalForwarder(ctx)
	go d.listenSocket(ctx)

	d.transition(ctx, StateInit, "startup")

	for {
		select {
		case ev := <-d.eventCh:
			d.handleEvent(ctx, ev)
			if d.state == StateShuttingDown {
				return
			}
		case <-ctx.Done():
			d.transition(ctx, StateShuttingDown, "context-cancelled")
			return
		}
	}
}

// signalForwarder converts OS signals into FSM events.
func (d *daemon) signalForwarder(ctx context.Context) {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				d.eventCh <- Event{Type: EvSIGTERM, Detail: sig.String()}
			case syscall.SIGHUP:
				d.eventCh <- Event{Type: EvSIGHUP}
			}
		case <-ctx.Done():
			return
		}
	}
}

// ===========================================================================
// Event dispatch
// ===========================================================================

func (d *daemon) handleEvent(ctx context.Context, ev Event) {
	// Events that fire in every state.
	switch ev.Type {
	case EvSIGTERM, EvSocketStop:
		if d.state != StateShuttingDown {
			d.transition(ctx, StateShuttingDown, ev.Type.String())
		}
		return
	case EvSocketStatus:
		if ev.Reply != nil {
			ev.Reply <- d.statusString()
		}
		return
	case EvRetry:
		log.Printf("retrying state %s", d.state)
		d.enterStateFn(ctx)
		return
	}

	switch d.state {
	case StateInit:
		d.handleInit(ctx, ev)
	case StateInstalling:
		d.handleInstalling(ctx, ev)
	case StateStartingCtrd:
		d.handleStartingCtrd(ctx, ev)
	case StateConfiguring:
		d.handleConfiguring(ctx, ev)
	case StateStartingK3s:
		d.handleStartingK3s(ctx, ev)
	case StateImporting:
		d.handleImporting(ctx, ev)
	case StateWaitK3sReady:
		d.handleWaitK3sReady(ctx, ev)
	case StateDeploying:
		d.handleDeploying(ctx, ev)
	case StateRunning:
		d.handleRunning(ctx, ev)
	case StateBackoff:
		d.handleBackoff(ctx, ev)
	case StateStoppingK3s:
		d.handleStoppingK3s(ctx, ev)
	case StateRunningHooks:
		d.handleRunningHooks(ctx, ev)
	case StateClusterTransition:
		d.handleClusterTransition(ctx, ev)
	case StateShuttingDown:
		// absorb everything
	}
}

// ===========================================================================
// State handlers
// ===========================================================================

func (d *daemon) handleInit(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvPrereqsDone:
		if d.initRes != nil {
			d.deviceName = d.initRes.deviceName
			d.uuid = d.initRes.uuid
			d.eveRelease = d.initRes.eveRelease
			d.installKubevirt = d.initRes.installKubevirt
			d.phase = d.initRes.phase
			d.initRes = nil
		}
		d.transition(ctx, StateInstalling, "prereqs-done")

	case EvError:
		d.lastError = ev.Err
		log.Printf("INIT error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)

	case EvSocketRestart, EvSIGHUP:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleInstalling(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvInstallDone:
		d.transition(ctx, StateStartingCtrd, "install-done")
	case EvError:
		d.lastError = ev.Err
		log.Printf("INSTALLING error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)
	case EvSocketRestart, EvSIGHUP:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleStartingCtrd(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvContainerdReady:
		d.transition(ctx, StateConfiguring, "containerd-ready")
	case EvError:
		d.lastError = ev.Err
		log.Printf("STARTING_CTRD error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)
	case EvSocketRestart, EvSIGHUP:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleConfiguring(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvConfigureDone:
		d.transition(ctx, StateStartingK3s, "configure-done")
	case EvError:
		d.lastError = ev.Err
		log.Printf("CONFIGURING error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)
	case EvSocketRestart, EvSIGHUP:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleStartingK3s(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvK3sStarted:
		d.k3sStartedAt = time.Now()
		d.lastError = nil
		// PhaseSteady routes through WaitK3sReady (not directly
		// to RUNNING) because EvK3sStarted only proves the
		// kubeconfig file appeared — k3s writes it before the
		// API listener is up. Going via WaitK3sReady forces a
		// real round-trip before enterRunning spawns goroutines
		// that will call kubectl. The wait against a healthy k3s
		// returns nearly instantly, so the extra state is cheap.
		switch d.phase {
		case PhaseFirstBoot:
			d.transition(ctx, StateImporting, "k3s-started/first-boot")
		case PhaseSteady:
			d.transition(ctx, StateWaitK3sReady, "k3s-started/restart")
		case PhaseRecycle:
			d.transition(ctx, StateImporting, "k3s-started/recycle")
		default:
			log.Printf("BUG: unknown phase %s in STARTING_K3S — routing to WaitK3sReady",
				d.phase)
			d.transition(ctx, StateWaitK3sReady, "k3s-started/unknown-phase")
		}

	case EvK3sExited:
		d.lastError = ev.Err
		log.Printf("k3s exited during startup: %v", ev.Err)
		d.computeBackoff()
		d.transition(ctx, StateBackoff, "k3s-exited-during-start")

	case EvError:
		d.lastError = ev.Err
		log.Printf("STARTING_K3S error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)

	case EvSocketRestart, EvSIGHUP, EvConfigChange, EvClusterRecycle:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleImporting(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvImagesDone:
		d.transition(ctx, StateWaitK3sReady, "images-done")

	case EvK3sExited:
		d.lastError = ev.Err
		log.Printf("k3s died during image import: %v", ev.Err)
		d.computeBackoff()
		d.transition(ctx, StateBackoff, "k3s-exited-during-import")

	case EvError:
		d.lastError = ev.Err
		log.Printf("IMPORTING error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)

	case EvSocketRestart, EvSIGHUP, EvConfigChange, EvClusterRecycle:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleWaitK3sReady(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvK3sReady:
		switch d.phase {
		case PhaseFirstBoot:
			d.transition(ctx, StateDeploying, "k3s-ready/first-boot")
		default:
			d.transition(ctx, StateRunning, "k3s-ready/skip-deploy")
		}

	case EvK3sExited:
		d.lastError = ev.Err
		log.Printf("k3s died while waiting for readiness: %v", ev.Err)
		d.computeBackoff()
		d.transition(ctx, StateBackoff, "k3s-exited-during-ready-wait")

	case EvError:
		d.lastError = ev.Err
		log.Printf("WAIT_K3S_READY error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)

	case EvSocketRestart, EvSIGHUP, EvConfigChange, EvClusterRecycle:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleDeploying(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvDeployDone:
		// Clear lastError so the status socket doesn't show a
		// stale DEPLOYING-retry error after a successful pass.
		d.lastError = nil
		d.phase = PhaseSteady
		d.transition(ctx, StateRunning, "deploy-done")

	case EvK3sExited:
		d.lastError = ev.Err
		log.Printf("k3s died during component deployment: %v", ev.Err)
		d.computeBackoff()
		d.transition(ctx, StateBackoff, "k3s-exited-during-deploy")

	case EvError:
		d.lastError = ev.Err
		log.Printf("DEPLOYING error: %v — retrying in %v", ev.Err, errorRetryDelay)
		d.retryCurrentState(ctx)

	case EvSocketRestart, EvSIGHUP, EvConfigChange, EvClusterRecycle:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleRunning(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvK3sExited:
		d.lastError = ev.Err
		if ev.Err != nil {
			log.Printf("k3s exited: %v", ev.Err)
		} else {
			log.Printf("k3s exited cleanly (unexpected in RUNNING)")
		}
		d.restartCount++
		monitor.SaveCrashLog(d.restartCount)
		d.computeBackoff()
		d.transition(ctx, StateBackoff, "k3s-crashed")

	case EvSocketRestart:
		d.restartReason = restartSocket
		d.backoff = minBackoff
		d.transition(ctx, StateStoppingK3s, "socket-restart")

	case EvSIGHUP:
		d.restartReason = restartSIGHUP
		d.backoff = minBackoff
		d.transition(ctx, StateStoppingK3s, "SIGHUP")

	case EvConfigChange:
		d.restartReason = restartConfigChange
		d.backoff = minBackoff
		d.transition(ctx, StateStoppingK3s, "config-change")

	case EvClusterRecycle:
		d.restartReason = restartFullRecycle
		d.backoff = minBackoff
		d.transition(ctx, StateStoppingK3s, "cluster-recycle")

	case EvSingleToCluster:
		// The clustermode runner drives Stop and RunHooks itself
		// (token rotation must happen while k3s is still
		// running), so we bypass STOPPING_K3S/RUNNING_HOOKS.
		d.restartReason = restartSingleToCluster
		d.backoff = minBackoff
		d.transition(ctx, StateClusterTransition, "single-to-cluster")

	case EvClusterToSingle:
		// One-shot cleanup + reboot. The runner does not return.
		d.restartReason = restartClusterToSingle
		d.backoff = minBackoff
		d.transition(ctx, StateClusterTransition, "cluster-to-single")

	case EvHealthTick:
		if d.mon == nil {
			break
		}
		if d.healthInflight {
			log.Printf("health worker still running, skipping tick")
			break
		}
		d.healthInflight = true
		// Snapshot mon and supervisor at spawn time so the
		// worker has stable references — leaving RUNNING nils
		// d.mon, and racing reads from the worker would either
		// nil-deref or trip the race detector.
		go d.runHealthWorker(d.runningCtx, d.mon, d.supervisor)

	case EvHealthDone:
		d.healthInflight = false

	case EvError:
		d.lastError = ev.Err
		log.Printf("RUNNING error: %v (non-fatal)", ev.Err)
	}
}

func (d *daemon) handleBackoff(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvBackoffExpired:
		d.phase = PhaseSteady
		d.transition(ctx, StateStartingK3s, "backoff-expired")

	case EvSocketRestart:
		d.stopBackoffTimer()
		d.restartReason = restartSocket
		d.backoff = minBackoff
		d.restartCount++
		// k3s is already dead in BACKOFF; skip STOPPING_K3S.
		d.transition(ctx, StateRunningHooks, "socket-restart-during-backoff")

	case EvSIGHUP:
		d.stopBackoffTimer()
		d.restartReason = restartSIGHUP
		d.backoff = minBackoff
		d.transition(ctx, StateRunningHooks, "SIGHUP-during-backoff")

	case EvConfigChange:
		d.stopBackoffTimer()
		d.restartReason = restartConfigChange
		d.backoff = minBackoff
		d.transition(ctx, StateRunningHooks, "config-change-during-backoff")

	case EvClusterRecycle:
		d.stopBackoffTimer()
		d.restartReason = restartFullRecycle
		d.backoff = minBackoff
		d.phase = PhaseRecycle
		d.transition(ctx, StateRunningHooks, "cluster-recycle-during-backoff")

	case EvK3sExited:
		// k3s may have been partially alive; absorb.
		log.Printf("absorbed EvK3sExited in BACKOFF (err=%v)", ev.Err)

	case EvError:
		d.lastError = ev.Err
		log.Printf("BACKOFF error: %v (ignored)", ev.Err)
	}
}

func (d *daemon) handleStoppingK3s(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvStopDone:
		reason := d.restartReason
		switch {
		case reason == restartFullRecycle:
			d.phase = PhaseRecycle
			d.transition(ctx, StateRunningHooks, "stop-done/recycle")
		case needsHooks(reason):
			d.transition(ctx, StateRunningHooks, "stop-done/hooks-needed")
		default:
			// Crash-style restart: no hooks.
			d.phase = PhaseSteady
			d.transition(ctx, StateStartingK3s, "stop-done/no-hooks")
		}

	case EvK3sExited:
		// k3s died while we were trying to stop it — absorb.
		// The Stop goroutine will still send EvStopDone after
		// cleanup completes.
		log.Printf("absorbed EvK3sExited during STOPPING_K3S")

	case EvSocketRestart, EvSIGHUP, EvConfigChange, EvClusterRecycle:
		d.queueRestart(restartForEvent(ev.Type))

	case EvError:
		d.lastError = ev.Err
		log.Printf("STOPPING_K3S error: %v — retrying stop", ev.Err)
		d.retryCurrentState(ctx)
	}
}

// handleClusterTransition is entered only from RUNNING via
// EvSingleToCluster or EvClusterToSingle. The async worker drives
// the supervisor itself, so on EvTransitionDone we go straight to
// StartingK3s with PhaseRecycle. The cluster→single path reboots
// inside the runner and does not return.
func (d *daemon) handleClusterTransition(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvTransitionDone:
		d.setTransitionStep("")
		d.restartCount = 0
		d.phase = PhaseRecycle
		d.transition(ctx, StateStartingK3s, "transition-done/recycle")

	case EvK3sExited:
		// Expected: the runner called Stop itself.
		log.Printf("absorbed EvK3sExited during CLUSTER_TRANSITION")

	case EvError:
		// Mid-flight transition failure. For non-bootstrap nodes
		// the monitor's CheckClusterTransitionDone watchdog will
		// eventually reboot. Otherwise we fall back to a recycle
		// path that re-enters CONFIGURING with fresh config.
		d.lastError = ev.Err
		failedStep := d.getTransitionStep()
		d.setTransitionStep("")
		log.Printf("CLUSTER_TRANSITION error at step %q: %v — falling back to recycle",
			failedStep, ev.Err)
		d.phase = PhaseRecycle
		d.transition(ctx, StateConfiguring, "transition-error/recycle")

	case EvSocketRestart, EvSIGHUP, EvConfigChange,
		EvClusterRecycle, EvSingleToCluster, EvClusterToSingle:
		// Do not interrupt a transition in flight — queue it.
		d.queueRestart(restartForEvent(ev.Type))
	}
}

func (d *daemon) handleRunningHooks(ctx context.Context, ev Event) {
	switch ev.Type {
	case EvHooksDone:
		reason := d.restartReason
		if reason == restartFullRecycle {
			d.phase = PhaseRecycle
			d.transition(ctx, StateConfiguring, "hooks-done/recycle")
		} else {
			d.phase = PhaseSteady
			d.transition(ctx, StateStartingK3s, "hooks-done/restart")
		}

	case EvError:
		// Hook errors are logged and we restart anyway: a hook
		// is operator-defined, and refusing to restart on a hook
		// failure traps a misconfigured device in a broken
		// state until manual intervention.
		d.lastError = ev.Err
		log.Printf("RUNNING_HOOKS error: %v — proceeding with restart", ev.Err)
		d.phase = PhaseSteady
		d.transition(ctx, StateStartingK3s, "hooks-error/proceeding")

	case EvSocketRestart, EvSIGHUP, EvConfigChange, EvClusterRecycle:
		d.queueRestart(restartForEvent(ev.Type))
	}
}

// ===========================================================================
// State transitions
// ===========================================================================

// transition moves the FSM from the current state to newState. It
// cancels in-flight async work, cleans up state-specific
// resources, logs the transition, and invokes enterStateFn.
func (d *daemon) transition(ctx context.Context, newState State, reason string) {
	oldState := d.state

	if d.cancelWork != nil {
		d.cancelWork()
		d.cancelWork = nil
	}

	// Cancel the k3s exit watcher when intentionally stopping k3s
	// so we don't see a spurious EvK3sExited racing the stop
	// completion.
	if newState == StateStoppingK3s || newState == StateShuttingDown {
		d.cancelExitWatcher()
	}

	if oldState == StateRunning && newState != StateRunning {
		if d.cancelRunning != nil {
			d.cancelRunning()
			d.cancelRunning = nil
		}
		d.stopHealthTicker()
		d.stopMonitor()
		// A health worker in flight will still post EvHealthDone,
		// but the new state's handler doesn't consume it. Reset
		// the gate so the next entry into RUNNING isn't stuck
		// dropping every EvHealthTick.
		d.healthInflight = false
	}

	if oldState == StateBackoff && newState != StateBackoff {
		d.stopBackoffTimer()
	}

	log.Printf("%s → %s (reason: %s)", oldState, newState, reason)
	d.state = newState
	d.enterStateFn(ctx)
}

// ===========================================================================
// State entry actions
// ===========================================================================

// enterState performs the entry action for the current state. Each
// entry action launches background work that eventually posts a
// completion event back to eventCh.
func (d *daemon) enterState(ctx context.Context) {
	switch d.state {

	case StateInit:
		d.startAsync(ctx, d.workInit, EvPrereqsDone)

	case StateInstalling:
		d.startAsync(ctx, d.workInstall, EvInstallDone)

	case StateStartingCtrd:
		d.startAsync(ctx, prereqs.StartContainerd, EvContainerdReady)

	case StateConfiguring:
		d.startAsync(ctx, d.workConfigure, EvConfigureDone)

	case StateStartingK3s:
		d.enterStartingK3s(ctx)

	case StateImporting:
		d.startAsync(ctx, func(workCtx context.Context) error {
			return images.ImportAll(workCtx, d.eveRelease, d.installKubevirt)
		}, EvImagesDone)

	case StateWaitK3sReady:
		d.startAsync(ctx, func(workCtx context.Context) error {
			return k3s.WaitReady(workCtx, readinessTimeout)
		}, EvK3sReady)

	case StateDeploying:
		d.startAsync(ctx, d.workDeploy, EvDeployDone)

	case StateRunning:
		d.enterRunning(ctx)

	case StateBackoff:
		d.enterBackoff()

	case StateStoppingK3s:
		d.enterStoppingK3s(ctx)

	case StateRunningHooks:
		d.startAsync(ctx, func(_ context.Context) error {
			if d.supervisor != nil {
				d.supervisor.RunHooks()
			}
			return nil
		}, EvHooksDone)

	case StateClusterTransition:
		d.enterClusterTransition(ctx)

	case StateShuttingDown:
		d.doShutdown()
	}
}

// workInit runs the prereqs pass, sets up the convert-to-single
// recovery flow, and computes the initial Phase. Output is stored
// in d.initRes for handleInit to publish into the daemon struct
// after EvPrereqsDone arrives.
func (d *daemon) workInit(workCtx context.Context) error {
	deviceName, uuid, eveRelease, err := prereqs.RunAll(workCtx)
	if err != nil {
		return err
	}

	res := initResult{
		deviceName:      deviceName,
		uuid:            uuid,
		eveRelease:      eveRelease,
		installKubevirt: true,
	}

	// KubeVirt is amd64-only upstream.
	if runtime.GOARCH != "amd64" {
		log.Printf("arch=%s — KubeVirt disabled", runtime.GOARCH)
		res.installKubevirt = false
	}

	baseMode, err := state.IsMarked(state.BaseK3sMode)
	if err != nil {
		return fmt.Errorf("check base-k3s mode: %w", err)
	}
	if baseMode {
		log.Printf("base-k3s mode — KubeVirt disabled")
		res.installKubevirt = false
	}

	pendingConvert, err := state.IsConvertToSingleNode()
	if err != nil {
		return fmt.Errorf("check convert-to-single-node marker: %w", err)
	}
	if pendingConvert {
		log.Printf("convert-to-single-node flag found — restoring /var/lib backup")
		// RestoreVarLib failure must abort: proceeding with the
		// cluster-mode /var/lib still on disk would start k3s
		// against mismatched certs/node-name and crash-loop in
		// BACKOFF with no breadcrumb pointing at the restore.
		if err := state.RestoreVarLib(); err != nil {
			return fmt.Errorf("convert-to-single: restore /var/lib (cannot proceed with mixed state): %w", err)
		}
		// Unmark failure must abort too: if the marker persists,
		// the next boot will again try to restore, this time over
		// the freshly-written single-node state — a self-
		// amplifying loop the marker pattern is meant to prevent.
		if err := state.Unmark(state.ConvertToSingleNode); err != nil {
			return fmt.Errorf("convert-to-single: unmark would cause restore loop on next boot: %w", err)
		}
		// MarkInitialized failure is recoverable: the worst case
		// is the daemon redoes first-boot deploy, which is
		// idempotent.
		if err := state.MarkInitialized(); err != nil {
			log.Printf("WARNING: mark initialized after restore: %v (first-boot deploy will re-run)", err)
		}
	}

	initialized, err := state.IsInitialized()
	if err != nil {
		return fmt.Errorf("check initialized: %w", err)
	}
	if initialized {
		res.phase = PhaseSteady
		log.Printf("previously initialized — using restart phase")
	} else {
		res.phase = PhaseFirstBoot
		log.Printf("first boot — full initialization required")
	}

	d.initRes = &res
	return nil
}

// workInstall checks the desired k3s version and runs
// EnsureInstalled. A failed download is non-fatal: install will
// proceed with whatever binary is already on disk so a transient
// network outage cannot trap a fresh device in INSTALLING forever.
func (d *daemon) workInstall(workCtx context.Context) error {
	updated, err := update.CheckNodeComponents(workCtx, d.supervisor)
	if err != nil {
		log.Printf("WARNING: k3s version check failed: %v (continuing with whatever is on disk)",
			err)
	} else if updated {
		log.Printf("k3s downloaded/updated — proceeding with install")
	}
	return k3s.EnsureInstalled(workCtx)
}

// workConfigure renders k3s drop-ins and pre-stages CNI plugins.
// A CNI staging failure is logged but does not block the FSM —
// the kubelet itself will retry the symlink lookups on every pod
// admission.
func (d *daemon) workConfigure(workCtx context.Context) error {
	if err := k3s.Configure(workCtx); err != nil {
		return err
	}
	if err := prereqs.CopyCNIPlugins(); err != nil {
		log.Printf("WARNING: CNI plugin copy: %v", err)
	}
	return nil
}

// workDeploy drives DeployAll and persists first-boot success
// markers. The /var/lib snapshot supports the cluster→single
// recovery path; a failure is logged but does not abort the
// deploy because the snapshot is only consulted on a later
// rebooted convert pass.
func (d *daemon) workDeploy(workCtx context.Context) error {
	if err := components.DeployAll(workCtx, d.deviceName, d.installKubevirt); err != nil {
		return err
	}

	log.Printf("saving /var/lib snapshot")
	if saveErr := state.SaveVarLib(); saveErr != nil {
		log.Printf("WARNING: /var/lib snapshot failed: %v", saveErr)
	}

	if err := state.MarkInitialized(); err != nil {
		return fmt.Errorf("mark initialized: %w", err)
	}
	if err := state.Mark(state.NodeLabelsInitialized); err != nil {
		log.Printf("WARNING: mark node labels initialized: %v", err)
	}

	log.Printf("first-time initialization complete")
	return nil
}

// enterClusterTransition launches the async transition worker.
// The worker drives Supervisor.Stop and RunHooks itself, so the
// FSM stays in StateClusterTransition for the entire sequence.
// The k3s exit watcher is cancelled first because the worker will
// intentionally stop k3s — without this we'd see a spurious
// EvK3sExited racing EvTransitionDone.
func (d *daemon) enterClusterTransition(ctx context.Context) {
	d.cancelExitWatcher()

	reason := d.restartReason
	log.Printf("CLUSTER_TRANSITION: reason=%s", restartReasonString(reason))

	d.setTransitionStep("starting")
	progress := func(step string) { d.setTransitionStep(step) }

	d.startAsync(ctx, func(workCtx context.Context) error {
		switch reason {
		case restartSingleToCluster:
			return clustermode.NewRunner(d.supervisor, progress).Run(workCtx)
		case restartClusterToSingle:
			d.setTransitionStep("cluster-to-single-reboot")
			return clustermode.RunClusterToSingle()
		default:
			return fmt.Errorf("unexpected restart reason in CLUSTER_TRANSITION: %s",
				restartReasonString(reason))
		}
	}, EvTransitionDone)
}

// enterStartingK3s creates or reuses the supervisor, starts k3s,
// and watches for the kubeconfig file. A stale running supervisor
// from a previous cycle is stopped first — a leaked instance
// would hold the API ports and the new Start would error with
// EADDRINUSE.
//
// On a cold boot in cluster mode this also applies the rank-
// based startup stagger (clustermode.ConsumeStartupRank) so
// simultaneous power-up of all control-plane nodes doesn't race
// etcd joins. The rank file is consumed on read so the delay
// only fires on the boot immediately after it was written.
func (d *daemon) enterStartingK3s(ctx context.Context) {
	if delay, ok := clustermode.ConsumeStartupRank(); ok {
		log.Printf("STARTING_K3S: applying staggered delay %s", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
	}

	// Restore the persisted k3s node password before any code path
	// can launch k3s. /etc/rancher/node/password lives on the kube
	// container's tmpfs overlay and would otherwise be regenerated
	// to a new random value on each reboot, causing the server to
	// log NodePasswordValidationFailed against the original hash
	// stored in <hostname>.node-password.k3s.
	if err := k3s.RestoreNodePassword(); err != nil {
		log.Printf("WARNING: restore node password: %v", err)
	}

	if d.supervisor != nil && d.supervisor.IsRunning() {
		log.Printf("stopping stale k3s instance before restart")
		if err := d.supervisor.Stop(); err != nil {
			// ErrPortsStillBound means a follow-up Start will
			// hit EADDRINUSE. Surfacing as EvError routes us to
			// retryCurrentState, which after a few rounds with
			// the orphan sweep usually resolves the bind.
			// Failing loud is critical: silently looping on
			// "stop stale supervisor" with no signal to the
			// status socket is the worst failure mode.
			if errors.Is(err, k3s.ErrPortsStillBound) {
				log.Printf("WARNING: k3s ports still bound after Stop: %v — surfacing as error",
					err)
				if ctx.Err() == nil {
					d.eventCh <- Event{Type: EvError, Err: err}
				}
				return
			}
			log.Printf("WARNING: stop stale supervisor: %v (continuing to Start)", err)
		}
	}

	if d.supervisor == nil {
		d.supervisor = k3s.NewSupervisor()
	}

	if err := d.supervisor.Start(); err != nil {
		log.Printf("failed to start k3s: %v", err)
		if ctx.Err() == nil {
			d.eventCh <- Event{Type: EvError, Err: fmt.Errorf("start k3s: %w", err)}
		}
		return
	}

	pid := d.supervisor.K3sPID()
	log.Printf("k3s started (pid=%d, phase=%s)", pid, d.phase)

	setIOPriority(pid)

	exitCtx, exitCancel := context.WithCancel(ctx)
	d.cancelExit = exitCancel
	go d.watchK3sExit(exitCtx)

	d.startAsync(ctx, func(workCtx context.Context) error {
		tCtx, tCancel := context.WithTimeout(workCtx, kubeconfigTimeout)
		defer tCancel()
		return k3s.WaitKubeconfig(tCtx)
	}, EvK3sStarted)
}

// enterRunning brings up the steady-state supporting goroutines:
// CNI DHCP daemon, monitor, monitor→event bridge, health ticker.
func (d *daemon) enterRunning(ctx context.Context) {
	pid := 0
	if d.supervisor != nil {
		pid = d.supervisor.K3sPID()
	}
	log.Printf("RUNNING — k3s pid=%d, phase=%s, restarts=%d",
		pid, d.phase, d.restartCount)

	// One-shot status line so operators can see the registration
	// state without scrolling through silent health-tick output.
	components.LogRegistrationStatus()

	// k3s is up and the supervisor is talking to it — persist the
	// node password it generated (or confirm the one we restored
	// still matches). Idempotent: equal contents = no-op. On a
	// brownfield first boot under this fix, this also arms the
	// stale-secret cleanup that runHealthWorker retries every tick.
	if err := k3s.SaveNodePassword(); err != nil {
		log.Printf("WARNING: save node password: %v", err)
	}

	// Start the CNI DHCP daemon eagerly. On PhaseSteady the
	// DeployAll graph (which used to launch the daemon as a
	// graph node) is skipped, so without the eager start the
	// daemon only comes up on the first health tick — potentially
	// 15+ seconds after RUNNING — which delays pod admission for
	// EVE apps using multus dhcp-IPAM. StartDHCPDaemon is
	// idempotent.
	if err := components.StartDHCPDaemon(); err != nil {
		log.Printf("warning: eager DHCP daemon start: %v", err)
	}

	// Ensure the exit watcher is active.
	if d.cancelExit == nil && d.supervisor != nil && d.supervisor.IsRunning() {
		exitCtx, exitCancel := context.WithCancel(ctx)
		d.cancelExit = exitCancel
		go d.watchK3sExit(exitCtx)
	}

	d.runningCtx, d.cancelRunning = context.WithCancel(ctx)

	d.mon = monitor.New(d.deviceName, d.uuid, d.eveRelease, d.installKubevirt)
	d.mon.StartWithRestartCh(d.runningCtx, d.monRestartCh)

	go d.bridgeMonitorRestarts(d.runningCtx)

	d.healthTicker = time.NewTicker(healthCheckInterval)
	go d.forwardHealthTicks(d.runningCtx)

	d.processPendingRestart()
}

func (d *daemon) enterBackoff() {
	log.Printf("BACKOFF — waiting %v before restart (restarts=%d)",
		d.backoff, d.restartCount)
	d.backoffTimer = time.AfterFunc(d.backoff, func() {
		d.eventCh <- Event{Type: EvBackoffExpired}
	})
}

func (d *daemon) enterStoppingK3s(ctx context.Context) {
	d.startAsync(ctx, func(_ context.Context) error {
		if d.supervisor != nil {
			return d.supervisor.Stop()
		}
		return nil
	}, EvStopDone)
}

// ===========================================================================
// Async work pattern
// ===========================================================================

// startAsync launches a goroutine to run fn. On success it sends
// doneEv; on error it sends EvError. If the work context is
// cancelled (because we transitioned to another state) the
// completion event is dropped so the new state's handler doesn't
// see stale results. A real error returned alongside a
// cancellation is logged before being dropped — without that,
// genuine failures vanish whenever the FSM happens to transition
// between the work returning and the channel send.
func (d *daemon) startAsync(ctx context.Context, fn func(context.Context) error, doneEv EventType) {
	workCtx, cancel := context.WithCancel(ctx)
	d.cancelWork = cancel

	go func() {
		err := fn(workCtx)
		if workCtx.Err() != nil {
			if err != nil &&
				!errors.Is(err, context.Canceled) &&
				!errors.Is(err, context.DeadlineExceeded) {
				log.Printf("WARNING: async work for %s returned err after cancellation (dropped): %v",
					doneEv, err)
			}
			return
		}
		if err != nil {
			d.eventCh <- Event{Type: EvError, Err: err}
			return
		}
		d.eventCh <- Event{Type: doneEv}
	}()
}

// ===========================================================================
// k3s exit watcher
// ===========================================================================

// watchK3sExit waits for the supervisor to report exit and posts
// EvK3sExited. Cancelled via cancelExit when we intentionally stop
// k3s ourselves so the FSM doesn't double-handle the exit.
func (d *daemon) watchK3sExit(ctx context.Context) {
	if d.supervisor == nil {
		return
	}
	select {
	case <-d.supervisor.Done():
		d.eventCh <- Event{Type: EvK3sExited, Err: d.supervisor.LastExit()}
	case <-ctx.Done():
	}
}

func (d *daemon) cancelExitWatcher() {
	if d.cancelExit != nil {
		d.cancelExit()
		d.cancelExit = nil
	}
}

// ===========================================================================
// Control socket
// ===========================================================================

// listenSocket serves the Unix-domain control socket. Started
// once at daemon boot so external tools can query status / request
// restarts during long INSTALLING passes.
func (d *daemon) listenSocket(ctx context.Context) {
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("WARNING: remove stale socket %s: %v", socketPath, err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		// Without the control socket the daemon has no
		// out-of-band restart/status/stop channel. Fail loudly
		// rather than running headless.
		log.Fatalf("listen on %s: %v", socketPath, err)
	}
	defer listener.Close()

	// World-writable so any in-container process can talk to it.
	if err := os.Chmod(socketPath, 0666); err != nil {
		log.Printf("WARNING: chmod %s: %v", socketPath, err)
	}

	log.Printf("control socket listening on %s", socketPath)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("socket accept: %v", err)
			continue
		}
		go d.handleSocketConn(conn)
	}
}

func (d *daemon) handleSocketConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	cmd := strings.TrimSpace(scanner.Text())

	switch cmd {
	case "restart":
		d.eventCh <- Event{Type: EvSocketRestart, Detail: "socket"}
		_, _ = conn.Write([]byte("OK: restart scheduled\n"))

	case "status":
		replyCh := make(chan string, 1)
		d.eventCh <- Event{Type: EvSocketStatus, Reply: replyCh}
		select {
		case resp := <-replyCh:
			_, _ = conn.Write([]byte(resp + "\n"))
		case <-time.After(3 * time.Second):
			_, _ = conn.Write([]byte("ERR: status timeout\n"))
		}

	case "stop":
		d.eventCh <- Event{Type: EvSocketStop, Detail: "socket"}
		_, _ = conn.Write([]byte("OK: stopping\n"))

	default:
		_, _ = conn.Write([]byte(fmt.Sprintf("ERR: unknown command: %s\n", cmd)))
	}
}

func (d *daemon) statusString() string {
	parts := []string{fmt.Sprintf("state=%s", d.state)}

	switch {
	case d.supervisor != nil && d.supervisor.IsRunning():
		parts = append(parts, fmt.Sprintf("k3s=pid:%d", d.supervisor.K3sPID()))
		if !d.k3sStartedAt.IsZero() {
			parts = append(parts, fmt.Sprintf("uptime=%s",
				time.Since(d.k3sStartedAt).Truncate(time.Second)))
		}
	case d.state == StateStoppingK3s:
		parts = append(parts, "k3s=stopping")
	case d.state == StateBackoff:
		parts = append(parts, "k3s=dead")
	default:
		parts = append(parts, "k3s=not-started")
	}

	parts = append(parts,
		fmt.Sprintf("backoff=%s", d.backoff),
		fmt.Sprintf("restarts=%d", d.restartCount),
		fmt.Sprintf("phase=%s", d.phase))

	if d.lastError != nil {
		parts = append(parts, fmt.Sprintf("last-error=%q", d.lastError.Error()))
	}
	if d.pendingRestart != nil {
		parts = append(parts,
			fmt.Sprintf("pending-restart=%s", restartReasonString(*d.pendingRestart)))
	}
	if d.state == StateClusterTransition {
		if step := d.getTransitionStep(); step != "" {
			parts = append(parts, fmt.Sprintf("transition-step=%s", step))
		}
	}
	return "OK: " + strings.Join(parts, " ")
}

// ===========================================================================
// Restart queuing
// ===========================================================================

// queueRestart stores a restart request for later processing.
// Higher-priority reasons override lower-priority ones — the
// numeric ordering of restartReason is the priority ordering, so
// a cluster recycle outranks a SIGHUP outranks a crash.
func (d *daemon) queueRestart(reason restartReason) {
	if d.pendingRestart == nil || reason > *d.pendingRestart {
		d.pendingRestart = &reason
		log.Printf("queued restart: %s (state=%s)",
			restartReasonString(reason), d.state)
	} else {
		log.Printf("restart already queued with higher priority (%s >= %s)",
			restartReasonString(*d.pendingRestart), restartReasonString(reason))
	}
}

// processPendingRestart re-posts a queued restart back into the
// event channel so handleRunning processes it through the normal
// path. Called on RUNNING entry from the run-loop goroutine; the
// channel send is done from a fresh goroutine so a transiently-
// full eventCh cannot deadlock the only reader.
func (d *daemon) processPendingRestart() {
	if d.pendingRestart == nil {
		return
	}
	reason := *d.pendingRestart
	d.pendingRestart = nil
	log.Printf("processing queued restart: %s", restartReasonString(reason))

	var ev Event
	switch reason {
	case restartSocket:
		ev = Event{Type: EvSocketRestart, Detail: "queued"}
	case restartSIGHUP:
		ev = Event{Type: EvSIGHUP, Detail: "queued"}
	case restartConfigChange:
		ev = Event{Type: EvConfigChange, Detail: "queued"}
	case restartFullRecycle:
		ev = Event{Type: EvClusterRecycle, Detail: "queued"}
	case restartSingleToCluster:
		ev = Event{Type: EvSingleToCluster, Detail: "queued"}
	case restartClusterToSingle:
		ev = Event{Type: EvClusterToSingle, Detail: "queued"}
	default:
		// A reason value outside the declared set indicates a bug
		// in the queue path (e.g. someone widened the enum without
		// updating this switch). Re-queue so the next entry into
		// RUNNING tries again and the BUG line stays visible.
		log.Printf("BUG: unknown queued restart reason %d — re-queueing",
			int(reason))
		d.pendingRestart = &reason
		return
	}

	// Send from a goroutine to avoid blocking the run loop on a
	// momentarily-full eventCh buffer.
	go func(e Event) { d.eventCh <- e }(ev)
}

// restartForEvent maps an inbound event to a restart reason for
// queueing. Unknown event types are not silently downgraded — they
// surface a BUG log line and fall through to restartSocket so the
// daemon still makes forward progress on a misrouted event.
func restartForEvent(evType EventType) restartReason {
	switch evType {
	case EvSocketRestart:
		return restartSocket
	case EvSIGHUP:
		return restartSIGHUP
	case EvConfigChange:
		return restartConfigChange
	case EvClusterRecycle:
		return restartFullRecycle
	case EvSingleToCluster:
		return restartSingleToCluster
	case EvClusterToSingle:
		return restartClusterToSingle
	}
	log.Printf("BUG: restartForEvent called with non-restart event %s — defaulting to socket-restart",
		evType)
	return restartSocket
}

// ===========================================================================
// Monitor → event bridge
// ===========================================================================

// bridgeMonitorRestarts converts monitor restart reasons into FSM
// events. The mapping is explicit per reason; an unknown reason
// falls through to EvConfigChange (the cheapest restart that
// still re-reads config) with a BUG log so a future monitor
// constant added without updating this switch is visible.
func (d *daemon) bridgeMonitorRestarts(ctx context.Context) {
	for {
		select {
		case reason := <-d.monRestartCh:
			d.bridgeOneMonitorRestart(reason)
		case <-ctx.Done():
			return
		}
	}
}

// bridgeOneMonitorRestart is the per-reason mapping, pulled out
// so it can be unit-tested without the channel/goroutine plumbing.
func (d *daemon) bridgeOneMonitorRestart(reason monitor.RestartReason) {
	var ev Event
	switch reason {
	case monitor.RestartFullRecycle:
		ev = Event{Type: EvClusterRecycle, Detail: "monitor"}
	case monitor.RestartConfigChange:
		ev = Event{Type: EvConfigChange, Detail: "monitor"}
	case monitor.RestartSingleToCluster:
		ev = Event{Type: EvSingleToCluster, Detail: "monitor"}
	case monitor.RestartClusterToSingle:
		ev = Event{Type: EvClusterToSingle, Detail: "monitor"}
	default:
		log.Printf("BUG: unknown monitor.RestartReason %d — defaulting to EvConfigChange",
			reason)
		ev = Event{
			Type:   EvConfigChange,
			Detail: fmt.Sprintf("monitor-reason-%d-unknown", reason),
		}
	}
	d.eventCh <- ev
}

// runHealthWorker runs the periodic health checks and the
// per-cluster-type steady-state actions in a worker goroutine. It
// always posts EvHealthDone back to the event loop (even on early
// return) so handleRunning can clear healthInflight.
//
// mon and sup are passed in (rather than read from d) so the
// worker holds stable references — the run loop nils d.mon when
// leaving RUNNING, and an unsynchronised read here would race or
// nil-deref.
func (d *daemon) runHealthWorker(ctx context.Context, mon *monitor.Monitor, sup *k3s.Supervisor) {
	defer func() {
		select {
		case d.eventCh <- Event{Type: EvHealthDone}:
		case <-ctx.Done():
		}
	}()

	if mon != nil {
		mon.RunHealthChecks(ctx)
		mon.CheckContainerd()
	}
	if ctx.Err() != nil {
		return
	}

	ct, err := k3s.GetClusterType()
	if err != nil {
		log.Printf("WARNING: get cluster type: %v", err)
		return
	}

	if err := components.RegistrationCheckApply(); err != nil {
		log.Printf("WARNING: registration check/apply: %v", err)
	}

	// SR-IOV manifest staging is per-tick + idempotent: hardware
	// detection via /sys/bus/pci, content-compare to avoid
	// rewriting the in-use sriov-cni binary, and the k3s auto-
	// deploy dir picks up the DaemonSet on next k3s reconcile.
	// No-op on non-SR-IOV hardware.
	if err := components.InstallSRIOVManifests(); err != nil {
		log.Printf("WARNING: install SR-IOV manifests: %v", err)
	}

	// Keep the stale-mount-cleanup daemon alive. It shares the
	// kubelet mount namespace (inside the kube container) and
	// reaps stale Longhorn CSI block-volume staging mounts that
	// would otherwise pin a deleted device inode and break every
	// subsequent NodePublishVolume against that PV. Restart-on-
	// exit is the desired behaviour; the per-tick call provides
	// it without a watchdog.
	if err := components.StartStaleMountCleanup(); err != nil {
		log.Printf("WARNING: start stale-mount-cleanup: %v", err)
	}

	// Brownfield remediation: if SaveNodePassword detected a
	// first-boot fresh-password case, it left a flag for us. Delete
	// the now-stale cluster secret so k3s regenerates it against
	// the password we persisted. No-op on every other boot.
	if err := k3s.FixNodePasswordSecret(ctx); err != nil {
		log.Printf("WARNING: fix node password secret: %v", err)
	}

	// mgmtproxy cni0 anchor: ensure CDI importer pods can reach the
	// local mgmtproxy via HTTPS_PROXY=CNI0URL. Two parts run every
	// tick because both are recovery paths for upgrades and flannel
	// restarts:
	//   - SetupCNI0ProxyIP re-applies the link-local anchor on cni0
	//     if it's missing (no-op if already present, skipped on
	//     cold boot before flannel creates cni0).
	//   - PatchCDIProxyConfig re-asserts the CDI CR's importProxy
	//     spec so importer pods get the proxy env; safe to repeat
	//     because kubectl patch is idempotent.
	// Both are gated on kubevirt being requested for this device —
	// base-k3s-mode and arm64 don't carry CDI.
	if d.installKubevirt {
		if res, err := mgmtproxy.SetupCNI0ProxyIP(); err != nil {
			log.Printf("WARNING: setup cni0 proxy anchor: %v", err)
		} else if res == mgmtproxy.CNI0Assigned {
			log.Printf("mgmtproxy: assigned %s/32 to cni0", mgmtproxy.CNI0IP)
		}
		if marked, err := state.IsMarked(state.KubevirtInitialized); err == nil && marked {
			if err := mgmtproxy.PatchCDIProxyConfig(ctx); err != nil {
				log.Printf("WARNING: patch CDI proxy config: %v", err)
			}
		}
	}

	if _, err := k3s.ApplyUserOverrides(); err != nil {
		log.Printf("WARNING: apply user overrides: %v", err)
	}

	d.runSteadyStateStorage(ctx, ct, sup)

	// Persist this node's control-plane rank for the next boot's
	// staggered startup, and (if the flag is armed) sweep stale
	// masterleases left from a recent single->cluster conversion.
	// Both are no-ops in single-node mode and after their work is
	// done; they share one GetClusterStatus read.
	if cs, err := k3s.GetClusterStatus(); err == nil {
		if rankErr := clustermode.SaveStartupRank(ctx, cs); rankErr != nil {
			log.Printf("WARNING: save startup rank: %v", rankErr)
		}
		if leaseErr := clustermode.CleanupStaleMasterleases(ctx, cs); leaseErr != nil {
			log.Printf("WARNING: masterleases cleanup: %v", leaseErr)
		}
	}

	if ct == k3s.ClusterTypeReplicated {
		// Per-tick controller-driven k3s drift check. Base mode
		// receives drift signals via the registration manifest
		// server, not via update-component, so this only fires
		// for replicated clusters.
		if updated, err := update.CheckNodeComponents(ctx, sup); err != nil {
			log.Printf("WARNING: k3s version check: %v", err)
		} else if updated {
			log.Printf("k3s updated; supervisor will restart on next exit")
		}

		if err := components.LonghornPostInstallConfig(); err != nil {
			log.Printf("WARNING: longhorn post-install config: %v", err)
		}

		if err := update.CheckClusterComponents(ctx); err != nil {
			log.Printf("WARNING: cluster component update: %v", err)
			return
		}
	}
}

// runSteadyStateStorage applies the storage-class policy that
// matches the active ClusterType. The policy is:
//
//   - Unspecified + registration applied: controller owns storage
//     via the registration manifest, so we remove our defaults to
//     avoid double-provisioning.
//   - Unspecified + no registration: ensure our default storage
//     classes are present (single-node case).
//   - Replicated: same as the no-registration unspecified case.
//   - Base: cluster member; defaults belong to the bootstrap node
//     only, so the local copy must be cleaned up.
//
// Skipped entirely until longhorn is initialised AND ready —
// otherwise the storage-class apply races a not-yet-deployed
// longhorn driver. The sup parameter is the supervisor snapshot
// from runHealthWorker.
func (d *daemon) runSteadyStateStorage(ctx context.Context, ct k3s.ClusterType, sup *k3s.Supervisor) {
	if sup == nil || !sup.IsRunning() {
		return
	}

	lhMarked, err := state.IsMarked(state.LonghornInitialized)
	if err != nil {
		log.Printf("WARNING: check longhorn-initialized: %v", err)
		return
	}
	if !lhMarked {
		return
	}
	lhReady, err := components.LonghornIsReady(ctx)
	if err != nil {
		log.Printf("WARNING: check longhorn ready: %v", err)
		return
	}
	if !lhReady {
		return
	}

	switch ct {
	case k3s.ClusterTypeUnspecified:
		if components.RegistrationApplied() {
			if err := components.CleanupStorageClasses(ctx); err != nil {
				log.Printf("WARNING: cleanup storage classes: %v", err)
			}
			components.LonghornPostInstallConfigClean()
		} else if err := components.EnsureStorageClasses(); err != nil {
			log.Printf("WARNING: ensure storage classes: %v", err)
		}

	case k3s.ClusterTypeReplicated:
		if err := components.EnsureStorageClasses(); err != nil {
			log.Printf("WARNING: ensure storage classes: %v", err)
		}

	case k3s.ClusterTypeBase:
		if err := components.CleanupStorageClasses(ctx); err != nil {
			log.Printf("WARNING: cleanup storage classes: %v", err)
		}
		components.LonghornPostInstallConfigClean()
	}
}

// forwardHealthTicks forwards ticker ticks onto eventCh. Drops
// ticks when the event channel is full — the FSM has a slower
// drain rate than the ticker only when the loop itself is wedged,
// at which point a missed tick is the least of our problems.
func (d *daemon) forwardHealthTicks(ctx context.Context) {
	if d.healthTicker == nil {
		return
	}
	for {
		select {
		case <-d.healthTicker.C:
			select {
			case d.eventCh <- Event{Type: EvHealthTick}:
			default:
			}
		case <-ctx.Done():
			return
		}
	}
}

// ===========================================================================
// Backoff logic
// ===========================================================================

// computeBackoff updates d.backoff based on how long k3s lasted.
// A long-stable run (> stableThreshold) resets to the minimum;
// otherwise we double-up to maxBackoff. This gives the loop a
// fast recovery on transient crashes while throttling a tight
// crash loop.
func (d *daemon) computeBackoff() {
	if !d.k3sStartedAt.IsZero() && time.Since(d.k3sStartedAt) > stableThreshold {
		d.backoff = minBackoff
		log.Printf("k3s was stable (ran %s) — backoff reset to %v",
			time.Since(d.k3sStartedAt).Truncate(time.Second), d.backoff)
		return
	}
	d.backoff *= 2
	if d.backoff > maxBackoff {
		d.backoff = maxBackoff
	}
	log.Printf("k3s was unstable — backoff increased to %v", d.backoff)
}

func (d *daemon) stopBackoffTimer() {
	if d.backoffTimer != nil {
		d.backoffTimer.Stop()
		d.backoffTimer = nil
	}
}

// ===========================================================================
// Health and monitor cleanup
// ===========================================================================

func (d *daemon) stopHealthTicker() {
	if d.healthTicker != nil {
		d.healthTicker.Stop()
		d.healthTicker = nil
	}
}

func (d *daemon) stopMonitor() {
	if d.mon != nil {
		d.mon.Stop()
		d.mon = nil
	}
}

// ===========================================================================
// Error retry
// ===========================================================================

// retryCurrentState re-enters the current state after errorRetryDelay.
// The delay goroutine respects cancellation so it won't fire if we
// transition away in the meantime.
func (d *daemon) retryCurrentState(ctx context.Context) {
	workCtx, cancel := context.WithCancel(ctx)
	d.cancelWork = cancel
	stateName := d.state.String() // snapshot for the goroutine
	go func() {
		select {
		case <-time.After(errorRetryDelay):
			select {
			case d.eventCh <- Event{Type: EvRetry, Detail: stateName}:
			case <-workCtx.Done():
			}
		case <-workCtx.Done():
		}
	}()
}

// ===========================================================================
// Shutdown
// ===========================================================================

// doShutdown stops k3s, the monitor, timers, and async work in
// order, then returns control to the run loop, which exits on
// seeing StateShuttingDown.
func (d *daemon) doShutdown() {
	log.Printf("shutting down")

	if d.cancelWork != nil {
		d.cancelWork()
		d.cancelWork = nil
	}
	d.cancelExitWatcher()
	d.stopMonitor()
	d.stopHealthTicker()
	d.stopBackoffTimer()

	if d.supervisor != nil && d.supervisor.IsRunning() {
		log.Printf("stopping k3s for shutdown")
		if err := d.supervisor.Stop(); err != nil {
			log.Printf("WARNING: stop k3s during shutdown: %v", err)
		}
	}

	log.Printf("shutdown complete")
}

// ===========================================================================
// I/O priority helper
// ===========================================================================

// setIOPriority sets best-effort I/O class with the highest
// priority for the given PID. Failures are logged but non-fatal —
// k3s runs fine without a tweaked ionice; the goal is to keep
// kube control-plane chatter ahead of bulk pod I/O on busy
// devices.
func setIOPriority(pid int) {
	if pid <= 0 {
		return
	}
	cmd := exec.Command("ionice", "-c2", "-n0", "-p", fmt.Sprintf("%d", pid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("WARNING: ionice pid=%d: %v (%s)", pid, err,
			strings.TrimSpace(string(out)))
		return
	}
	log.Printf("ionice: best-effort/0 set for k3s pid=%d", pid)
}
