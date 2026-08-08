// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"sync"
)

// Signal names a readiness condition that one component produces and
// others consume. Typed so a mistyped constant fails to compile; names
// are still validated at graph build for dynamically-built values.
type Signal string

// Signals produced by the component graph.
const (
	// MultusCNIReady holds once the multus DaemonSet is Available, which
	// is when 00-multus.conf — the node's primary CNI config — is in
	// place. Components that create pods must wait for it.
	MultusCNIReady Signal = "MultusCNIReady"

	// LonghornReady holds once the Longhorn DaemonSets are Available and
	// the Node CR for this host exists.
	LonghornReady Signal = "LonghornReady"

	// EveKubeAppNamespaceExists holds once the namespace that hosts EVE
	// app workloads is present.
	EveKubeAppNamespaceExists Signal = "EveKubeAppNamespaceExists"

	// CDIOperatorReady holds once cdi-operator is Available. The operator
	// serves the admission webhook for its own CR, so the CR must not be
	// applied before this.
	CDIOperatorReady Signal = "CDIOperatorReady"

	// CDIReady holds once the CDI CR reports phase=Deployed, which is
	// when uploadproxy and the importers exist.
	CDIReady Signal = "CDIReady"
)

// externalSignals holds signals emitted from outside the component
// graph — by prereqs, the monitor, or a pre-restart hook. A Requires
// naming one of these resolves to a runtime Bus.Await instead of a
// dependency edge.
//
// Empty today: every signal the graph consumes is also produced by it.
// Registering a signal here is what distinguishes a real external
// producer from a typo, which would otherwise stall forever.
var externalSignals = map[Signal]bool{}

// resolveSignals maps each component's Requires onto either a dependency
// edge (producer is in the graph) or a runtime Await (producer is
// external), and rejects a signal that has no producer at all.
func resolveSignals(components []Component) ([]Edge, map[string][]Signal, error) {
	producer := make(map[Signal]string, len(components))
	for i := range components {
		c := &components[i]
		for _, s := range c.Emits {
			if prev, dup := producer[s]; dup {
				return nil, nil, fmt.Errorf(
					"signal %q emitted by both %q and %q; ownership must be unambiguous",
					s, prev, c.Name)
			}
			producer[s] = c.Name
		}
	}

	var edges []Edge
	awaits := make(map[string][]Signal)
	for i := range components {
		c := &components[i]
		for _, s := range c.Requires {
			switch {
			case producer[s] == c.Name:
				return nil, nil, fmt.Errorf(
					"component %q requires signal %q that it emits itself", c.Name, s)
			case producer[s] != "":
				edges = append(edges, Edge{
					From: producer[s], To: c.Name, Rule: "signal", Signal: s,
				})
			case externalSignals[s]:
				awaits[c.Name] = append(awaits[c.Name], s)
			default:
				return nil, nil, fmt.Errorf(
					"component %q requires signal %q which no component emits and "+
						"which is not registered as an external signal", c.Name, s)
			}
		}
	}
	return edges, awaits, nil
}

// Bus carries signals whose producer sits outside the component graph
// (prereqs, the monitor, a pre-restart hook). Signals produced inside
// the graph are resolved to edges at plan time instead and never reach
// the Bus.
//
// Signals latch: once set they stay set for the life of the process.
// There is deliberately no Retract — a consumer that happened to Await
// inside a retract window would block until something re-emitted, and
// nothing today reconciles that. Bus state is per process; marker files
// carry idempotency across reboots.
type Bus struct {
	mu      sync.Mutex
	set     map[Signal]bool
	waiters map[Signal][]chan struct{}
}

// NewBus returns an empty Bus.
func NewBus() *Bus {
	return &Bus{
		set:     make(map[Signal]bool),
		waiters: make(map[Signal][]chan struct{}),
	}
}

// signalWaiter pairs a signal a caller is blocked on with the channel
// Emit closes to release it.
type signalWaiter struct {
	sig Signal
	ch  chan struct{}
}

// Emit latches s and releases everyone waiting on it. Idempotent —
// BestEffort background retries re-run Ready and would otherwise emit
// more than once.
func (b *Bus) Emit(s Signal) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.set[s] {
		return
	}
	b.set[s] = true
	for _, ch := range b.waiters[s] {
		close(ch)
	}
	delete(b.waiters, s)
}

// Await blocks until every signal in sigs has been emitted, or ctx is
// done. The error names the signal still outstanding — without that a
// timeout here is unactionable.
func (b *Bus) Await(ctx context.Context, sigs ...Signal) error {
	// The set check and waiter registration must happen under one lock
	// hold; an Emit landing between them would be missed.
	b.mu.Lock()
	var pending []signalWaiter
	for _, s := range sigs {
		if b.set[s] {
			continue
		}
		ch := make(chan struct{})
		b.waiters[s] = append(b.waiters[s], ch)
		pending = append(pending, signalWaiter{sig: s, ch: ch})
	}
	b.mu.Unlock()

	for _, p := range pending {
		select {
		case <-p.ch:
		case <-ctx.Done():
			b.drop(pending)
			return fmt.Errorf("deploy: await signal %s: %w", p.sig, ctx.Err())
		}
	}
	return nil
}

// drop unregisters channels left behind by an abandoned Await so the
// waiter map cannot grow across repeated BestEffort retries.
func (b *Bus) drop(pending []signalWaiter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range pending {
		w := b.waiters[p.sig]
		for i, ch := range w {
			if ch == p.ch {
				b.waiters[p.sig] = append(w[:i], w[i+1:]...)
				break
			}
		}
		if len(b.waiters[p.sig]) == 0 {
			delete(b.waiters, p.sig)
		}
	}
}

// Snapshot returns the signals latched so far. Used by the control
// socket to report readiness state.
func (b *Bus) Snapshot() map[Signal]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[Signal]bool, len(b.set))
	for s, v := range b.set {
		out[s] = v
	}
	return out
}
