// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBusAwaitAfterEmitReturnsImmediately(t *testing.T) {
	b := NewBus()
	b.Emit(MultusCNIReady)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Await(ctx, MultusCNIReady); err != nil {
		t.Fatalf("Await: %v", err)
	}
}

func TestBusAwaitUnblocksOnLaterEmit(t *testing.T) {
	b := NewBus()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- b.Await(ctx, LonghornReady) }()

	// Await must still be blocked: nothing has emitted yet.
	select {
	case err := <-done:
		t.Fatalf("Await returned before Emit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	b.Emit(LonghornReady)
	if err := <-done; err != nil {
		t.Fatalf("Await after Emit: %v", err)
	}
}

func TestBusAwaitWaitsForEverySignal(t *testing.T) {
	b := NewBus()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- b.Await(ctx, MultusCNIReady, LonghornReady, EveKubeAppNamespaceExists)
	}()

	b.Emit(MultusCNIReady)
	b.Emit(EveKubeAppNamespaceExists)
	select {
	case err := <-done:
		t.Fatalf("Await returned with LonghornReady outstanding: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	b.Emit(LonghornReady)
	if err := <-done; err != nil {
		t.Fatalf("Await: %v", err)
	}
}

// The timeout error must name the outstanding signal — a bare
// DeadlineExceeded gives an operator nothing to act on.
func TestBusAwaitTimeoutNamesOutstandingSignal(t *testing.T) {
	b := NewBus()
	b.Emit(MultusCNIReady)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := b.Await(ctx, MultusCNIReady, LonghornReady)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want DeadlineExceeded in chain, got %v", err)
	}
	if !strings.Contains(err.Error(), string(LonghornReady)) {
		t.Errorf("error should name %s, got %q", LonghornReady, err)
	}
	if strings.Contains(err.Error(), string(MultusCNIReady)) {
		t.Errorf("error should not name the already-satisfied signal, got %q", err)
	}
}

func TestBusEmitIsIdempotent(t *testing.T) {
	b := NewBus()
	// A second Emit must not close an already-closed channel.
	b.Emit(LonghornReady)
	b.Emit(LonghornReady)
	b.Emit(LonghornReady)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := b.Await(ctx, LonghornReady); err != nil {
		t.Fatalf("Await: %v", err)
	}
}

// An abandoned Await must not leave its channel registered, or the
// waiter map grows every time a BestEffort component retries.
func TestBusCancelledAwaitLeavesNoWaiter(t *testing.T) {
	b := NewBus()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if err := b.Await(ctx, LonghornReady); err == nil {
		t.Fatal("expected timeout")
	}

	b.mu.Lock()
	n := len(b.waiters)
	b.mu.Unlock()
	if n != 0 {
		t.Errorf("waiters map has %d entries after cancelled Await, want 0", n)
	}
}

func TestBusSnapshotReportsLatchedSignals(t *testing.T) {
	b := NewBus()
	if got := len(b.Snapshot()); got != 0 {
		t.Errorf("fresh bus snapshot has %d entries, want 0", got)
	}
	b.Emit(MultusCNIReady)

	snap := b.Snapshot()
	if !snap[MultusCNIReady] {
		t.Error("snapshot missing MultusCNIReady")
	}
	if snap[LonghornReady] {
		t.Error("snapshot reports un-emitted LonghornReady")
	}

	// Snapshot must be a copy — mutating it cannot affect the Bus.
	snap[LonghornReady] = true
	if b.Snapshot()[LonghornReady] {
		t.Error("Snapshot returned a live reference to Bus state")
	}
}

// ---------------------------------------------------------------------------
// Signal resolution at graph build
// ---------------------------------------------------------------------------

func TestSignalRequiresWithNoProducerFailsBuild(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "consumer", Requires: []Signal{LonghornReady}},
	}}
	_, err := g.Edges()
	if err == nil {
		t.Fatal("expected build error for signal with no producer")
	}
	if !strings.Contains(err.Error(), string(LonghornReady)) {
		t.Errorf("error should name the unproduced signal, got %q", err)
	}
}

func TestSignalEmittedByTwoComponentsFailsBuild(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Emits: []Signal{LonghornReady}},
		{Name: "b", Emits: []Signal{LonghornReady}},
	}}
	_, err := g.Edges()
	if err == nil {
		t.Fatal("expected build error for ambiguous signal ownership")
	}
	for _, want := range []string{"a", "b", string(LonghornReady)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got %q", want, err)
		}
	}
}

func TestSignalSelfRequireFailsBuild(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Emits: []Signal{LonghornReady}, Requires: []Signal{LonghornReady}},
	}}
	if _, err := g.Edges(); err == nil {
		t.Fatal("expected build error for component requiring a signal it emits")
	}
}

func TestSignalResolvesToEdge(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "producer", Emits: []Signal{MultusCNIReady}},
		{Name: "consumer", Requires: []Signal{MultusCNIReady}},
	}}
	edges, err := g.Edges()
	if err != nil {
		t.Fatalf("Edges: %v", err)
	}
	want := Edge{From: "producer", To: "consumer", Rule: "signal", Signal: MultusCNIReady}
	if len(edges) != 1 || edges[0] != want {
		t.Errorf("edges = %+v, want exactly %+v", edges, want)
	}
}

func TestSignalCycleIsDetected(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Emits: []Signal{MultusCNIReady}, Requires: []Signal{LonghornReady}},
		{Name: "b", Emits: []Signal{LonghornReady}, Requires: []Signal{MultusCNIReady}},
	}}
	_, err := g.Edges()
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error should mention a cycle, got %q", err)
	}
}

// A signal registered as externally produced resolves to a runtime
// Await rather than an edge, and the component blocks until it lands.
func TestSignalExternalProducerResolvesToAwait(t *testing.T) {
	const external Signal = "TestExternalSignal"
	externalSignals[external] = true
	t.Cleanup(func() { delete(externalSignals, external) })

	var ran bool
	bus := NewBus()
	g := Graph{
		Bus: bus,
		Components: []Component{{
			Name:     "waiter",
			Requires: []Signal{external},
			Apply:    func(context.Context) error { ran = true; return nil },
		}},
	}

	// No edge is synthesized for an external signal.
	edges, err := g.Edges()
	if err != nil {
		t.Fatalf("Edges: %v", err)
	}
	if len(edges) != 0 {
		t.Errorf("external signal should not synthesize an edge, got %+v", edges)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	select {
	case <-done:
		t.Fatal("Run returned before the external signal was emitted")
	case <-time.After(50 * time.Millisecond):
	}
	if ran {
		t.Error("Apply ran before its external signal was emitted")
	}

	bus.Emit(external)
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ran {
		t.Error("Apply never ran after the external signal was emitted")
	}
}

func TestSignalConsumerRunsAfterProducer(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }

	bus := NewBus()
	g := Graph{
		Bus: bus,
		Components: []Component{
			{
				Name:  "consumer",
				Apply: func(context.Context) error { record("consumer"); return nil },
				// Requires must gate Apply even though "consumer"
				// sorts before "producer".
				Requires: []Signal{MultusCNIReady},
			},
			{
				Name:  "producer",
				Apply: func(context.Context) error { record("producer-apply"); return nil },
				Ready: func(context.Context) error { record("producer-ready"); return nil },
				Emits: []Signal{MultusCNIReady},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"producer-apply", "producer-ready", "consumer"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
	if !bus.Snapshot()[MultusCNIReady] {
		t.Error("producer completed but its signal was not emitted")
	}
}

// A BestEffort producer that fails still releases its dependents via the
// scheduling edge, but must not emit — the condition does not hold.
func TestSignalNotEmittedWhenBestEffortProducerFails(t *testing.T) {
	var consumerRan bool
	bus := NewBus()
	g := Graph{
		Bus: bus,
		Components: []Component{
			{
				Name:       "producer",
				BestEffort: true,
				Apply:      func(context.Context) error { return errors.New("boom") },
				Emits:      []Signal{LonghornReady},
			},
			{
				Name:     "consumer",
				Requires: []Signal{LonghornReady},
				Apply:    func(context.Context) error { consumerRan = true; return nil },
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Run(ctx); err != nil {
		t.Fatalf("Run should tolerate a BestEffort failure: %v", err)
	}
	if !consumerRan {
		t.Error("consumer should still run: BestEffort failure does not block downstream")
	}
	if bus.Snapshot()[LonghornReady] {
		t.Error("signal must not be emitted when its producer failed")
	}
}

// Run with -race: concurrent Emit and Await must not race, and every
// waiter must be released exactly once.
func TestBusConcurrentEmitAndAwait(t *testing.T) {
	b := NewBus()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const waiters = 24
	var wg sync.WaitGroup
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.Await(ctx, MultusCNIReady, LonghornReady); err != nil {
				errs <- err
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Emit(MultusCNIReady)
			b.Emit(LonghornReady)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Await failed: %v", err)
	}
}

// A BestEffort component that misses its in-graph Ready window but
// converges on a background retry must publish its signal then. Observed
// on a device: Longhorn timed out in-graph, converged ~13min later via
// retry, and LonghornReady stayed unset — so the status socket
// under-reported a healthy component and any out-of-graph consumer would
// have awaited it forever.
func TestSignalEmittedByBestEffortRetry(t *testing.T) {
	bus := NewBus()
	var attempts int32

	g := Graph{
		Bus:      bus,
		RetryCtx: context.Background(),
		RetryPolicy: RetryPolicy{
			Initial:     5 * time.Millisecond,
			Factor:      1.0,
			Cap:         5 * time.Millisecond,
			MaxAttempts: 5,
		},
		Components: []Component{{
			Name:       "slowpoke",
			BestEffort: true,
			Emits:      []Signal{LonghornReady},
			Ready: func(context.Context) error {
				// Fail the in-graph attempt, succeed on the first retry.
				if atomic.AddInt32(&attempts, 1) == 1 {
					return errors.New("not converged yet")
				}
				return nil
			},
		}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Run(ctx); err != nil {
		t.Fatalf("Run should tolerate the BestEffort failure: %v", err)
	}

	// Run returns before the background retry finishes, so the signal
	// must arrive via the retry loop.
	if bus.Snapshot()[LonghornReady] {
		t.Fatal("signal emitted despite the in-graph Ready failing")
	}
	awaitCtx, awaitCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer awaitCancel()
	if err := bus.Await(awaitCtx, LonghornReady); err != nil {
		t.Errorf("retry succeeded but never emitted the signal: %v", err)
	}
}
