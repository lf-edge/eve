// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nop is the zero-work Apply used by test fixtures whose only
// purpose is to exercise the scheduler's ordering / validation
// paths without any side effects.
func nop(_ context.Context) error { return nil }

// ---------------------------------------------------------------------------
// plan() validation
// ---------------------------------------------------------------------------

func TestPlanEmptyGraph(t *testing.T) {
	edges, order, _, err := Graph{}.plan()
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if edges != nil || order != nil {
		t.Errorf("empty graph: edges=%v order=%v, want nil/nil", edges, order)
	}
}

func TestPlanRejectsEmptyName(t *testing.T) {
	g := Graph{Components: []Component{{Name: "", Apply: nop}}}
	if _, _, _, err := g.plan(); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestPlanRejectsDuplicateName(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Apply: nop},
		{Name: "a", Apply: nop},
	}}
	_, _, _, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestPlanRejectsUnknownPolicyDep(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Apply: nop, PolicyDeps: []string{"ghost"}},
	}}
	_, _, _, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected unknown-dep error, got %v", err)
	}
}

func TestPlanRejectsSelfDep(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Apply: nop, PolicyDeps: []string{"a"}},
	}}
	_, _, _, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("expected self-dep error, got %v", err)
	}
}

func TestPlanRejectsCycle(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Apply: nop, PolicyDeps: []string{"b"}},
		{Name: "b", Apply: nop, PolicyDeps: []string{"c"}},
		{Name: "c", Apply: nop, PolicyDeps: []string{"a"}},
	}}
	_, _, _, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Edges() and edge-rule tagging
// ---------------------------------------------------------------------------

func TestEdgesTagsPolicyRule(t *testing.T) {
	g := Graph{Components: []Component{
		{Name: "a", Apply: nop},
		{Name: "b", Apply: nop, PolicyDeps: []string{"a"}},
	}}
	edges, err := g.Edges()
	if err != nil {
		t.Fatalf("Edges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("edges = %v, want 1", edges)
	}
	if edges[0] != (Edge{From: "a", To: "b", Rule: "policy"}) {
		t.Errorf("edge = %+v, want {a b policy}", edges[0])
	}
}

func TestEdgesSortedDeterministically(t *testing.T) {
	// Component insertion order intentionally scrambled to prove the
	// output is not just insertion order.
	g := Graph{Components: []Component{
		{Name: "z", Apply: nop, PolicyDeps: []string{"a"}},
		{Name: "b", Apply: nop, PolicyDeps: []string{"a"}},
		{Name: "a", Apply: nop},
	}}
	edges, err := g.Edges()
	if err != nil {
		t.Fatalf("Edges: %v", err)
	}
	want := []Edge{
		{From: "a", To: "b", Rule: "policy"},
		{From: "a", To: "z", Rule: "policy"},
	}
	if len(edges) != len(want) {
		t.Fatalf("edges = %v, want %v", edges, want)
	}
	for i := range edges {
		if edges[i] != want[i] {
			t.Errorf("edges[%d] = %+v, want %+v", i, edges[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Run — dependency ordering
// ---------------------------------------------------------------------------

func TestRunInDependencyOrder(t *testing.T) {
	var order []string
	var mu sync.Mutex
	record := func(name string) StepFunc {
		return func(_ context.Context) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}
	}
	g := Graph{
		MaxParallel: 1, // force serial so order is deterministic
		Components: []Component{
			{Name: "a", Apply: record("a")},
			{Name: "b", Apply: record("b"), PolicyDeps: []string{"a"}},
			{Name: "c", Apply: record("c"), PolicyDeps: []string{"b"}},
		},
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !equalStrings(order, []string{"a", "b", "c"}) {
		t.Errorf("order = %v, want [a b c]", order)
	}
}

// TestRunStartsIndependentComponentsInParallel: a fast component
// whose deps are satisfied starts immediately, not blocked on a
// slow unrelated peer.
func TestRunStartsIndependentComponentsInParallel(t *testing.T) {
	slowRunning := make(chan struct{})
	fastStarted := make(chan struct{})
	g := Graph{Components: []Component{
		{Name: "slow", Apply: func(c context.Context) error {
			close(slowRunning)
			// Block until fast has started; if we returned first,
			// this test would be trivially true even for a wave-
			// runner. Blocking guarantees fast started concurrently.
			<-fastStarted
			return nil
		}},
		{Name: "fast", Apply: func(c context.Context) error {
			<-slowRunning // wait until slow is actually mid-flight
			close(fastStarted)
			return nil
		}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := g.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error propagation and cancellation
// ---------------------------------------------------------------------------

func TestRunPropagatesApplyError(t *testing.T) {
	want := errors.New("boom")
	g := Graph{Components: []Component{
		{Name: "a", Apply: func(_ context.Context) error { return want }},
		{Name: "b", Apply: nop, PolicyDeps: []string{"a"}},
	}}
	err := g.Run(context.Background())
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want chain containing %v", err, want)
	}
	if !strings.Contains(err.Error(), `"a" apply`) {
		t.Errorf("err should mention component + step, got %v", err)
	}
}

func TestRunPropagatesReadyError(t *testing.T) {
	want := errors.New("not ready")
	g := Graph{Components: []Component{
		{Name: "a", Apply: nop, Ready: func(_ context.Context) error { return want }},
	}}
	err := g.Run(context.Background())
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want chain containing %v", err, want)
	}
	if !strings.Contains(err.Error(), `"a" ready`) {
		t.Errorf("err should mention ready step, got %v", err)
	}
}

func TestRunCancelsPeersOnFirstFailure(t *testing.T) {
	failing := errors.New("first")
	var blockerCancelled atomic.Bool
	g := Graph{Components: []Component{
		{Name: "fast-fail", Apply: func(_ context.Context) error { return failing }},
		{Name: "blocker", Apply: func(c context.Context) error {
			<-c.Done()
			blockerCancelled.Store(true)
			return c.Err()
		}},
	}}
	if err := g.Run(context.Background()); err == nil {
		t.Fatal("expected error, got nil")
	}
	if !blockerCancelled.Load() {
		t.Error("blocker was not cancelled when peer failed")
	}
}

func TestRunRespectsParentContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := Graph{Components: []Component{
		{Name: "blocker", Apply: func(c context.Context) error {
			<-c.Done()
			return c.Err()
		}},
	}}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := g.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled in chain", err)
	}
}

func TestRunReportsErrorsAlphabetically(t *testing.T) {
	// Both fail concurrently (no deps between them). The runner
	// picks the alphabetically-first failure as the head; the other
	// appears in the "(also: ...)" suffix.
	errA := errors.New("a failed")
	errC := errors.New("c failed")
	g := Graph{Components: []Component{
		{Name: "z", Apply: nop},
		{Name: "c", Apply: func(_ context.Context) error { return errC }},
		{Name: "a", Apply: func(_ context.Context) error { return errA }},
	}}
	err := g.Run(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errA) {
		t.Errorf("head error = %v, want chain containing %v", err, errA)
	}
	if !strings.Contains(err.Error(), `"c"`) {
		t.Errorf("err should mention secondary failure 'c': %v", err)
	}
}

// ---------------------------------------------------------------------------
// BestEffort semantics
// ---------------------------------------------------------------------------

func TestBestEffortApplyFailureNotPropagated(t *testing.T) {
	want := errors.New("optional component down")
	g := Graph{Components: []Component{
		{Name: "opt", Apply: func(_ context.Context) error { return want },
			BestEffort: true},
		{Name: "downstream", Apply: nop, PolicyDeps: []string{"opt"}},
	}}
	if err := g.Run(context.Background()); err != nil {
		t.Errorf("BestEffort apply failure should not propagate, got %v", err)
	}
}

func TestBestEffortReadyTimeoutSurfacesAsSuccess(t *testing.T) {
	var readyEnteredAt time.Time
	g := Graph{Components: []Component{
		{
			Name:  "slow",
			Apply: nop,
			Ready: func(c context.Context) error {
				readyEnteredAt = time.Now()
				<-c.Done()
				return c.Err()
			},
			BestEffort:   true,
			ReadyTimeout: 50 * time.Millisecond,
		},
	}}
	start := time.Now()
	err := g.Run(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("BestEffort timeout should not propagate, got %v", err)
	}
	if readyEnteredAt.IsZero() {
		t.Fatal("Ready was never called")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("BestEffort ready wait took %v; should be bounded near 50ms", elapsed)
	}
}

func TestBestEffortReadyTimeoutDefaultApplied(t *testing.T) {
	if defaultReadyTimeout <= 0 {
		t.Errorf("defaultReadyTimeout = %v, want > 0", defaultReadyTimeout)
	}
}

func TestNonBestEffortReadyRespectsCallerCtx(t *testing.T) {
	// Sanity: a non-BestEffort Ready with zero ReadyTimeout runs
	// under the caller's ctx. Deadline in the caller's ctx should
	// surface as the error.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	g := Graph{Components: []Component{
		{Name: "slow", Apply: nop, Ready: func(c context.Context) error {
			<-c.Done()
			return c.Err()
		}},
	}}
	err := g.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

// ---------------------------------------------------------------------------
// MaxParallel + Ready invariants
// ---------------------------------------------------------------------------

func TestMaxParallelLimitsConcurrency(t *testing.T) {
	const N = 4
	var inflight, peak int64
	apply := func(_ context.Context) error {
		now := atomic.AddInt64(&inflight, 1)
		if now > atomic.LoadInt64(&peak) {
			atomic.StoreInt64(&peak, now)
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&inflight, -1)
		return nil
	}
	components := make([]Component, N)
	for i := range components {
		components[i] = Component{Name: fmt.Sprintf("n%d", i), Apply: apply}
	}
	g := Graph{Components: components, MaxParallel: 2}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if peak > 2 {
		t.Errorf("peak in-flight = %d, want <= 2", peak)
	}
}

func TestReadyOnlyRunsWhenApplySucceeds(t *testing.T) {
	var readyCalled atomic.Bool
	g := Graph{Components: []Component{
		{
			Name:  "a",
			Apply: func(_ context.Context) error { return errors.New("apply failed") },
			Ready: func(_ context.Context) error {
				readyCalled.Store(true)
				return nil
			},
		},
	}}
	_ = g.Run(context.Background())
	if readyCalled.Load() {
		t.Error("Ready should not run when Apply fails")
	}
}

// TestComponentWithoutApplyIsValid — a Component may consist only
// of a Ready predicate (e.g. a marker that waits on an
// externally-installed CR). Apply=nil is a legitimate configuration
// and must not fail validation.
func TestComponentWithoutApplyIsValid(t *testing.T) {
	var readyCalled atomic.Bool
	g := Graph{Components: []Component{
		{Name: "wait-only", Ready: func(_ context.Context) error {
			readyCalled.Store(true)
			return nil
		}},
	}}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !readyCalled.Load() {
		t.Error("Ready was not called for Apply=nil component")
	}
}

// ---------------------------------------------------------------------------
// BestEffort background retry loop
// ---------------------------------------------------------------------------

// shortRetryPolicy is what every retry test uses so the loop
// exercises real backoff arithmetic without wall-clock delays that
// would make the test suite slow / flaky.
var shortRetryPolicy = RetryPolicy{
	Initial:     5 * time.Millisecond,
	Factor:      2.0,
	Cap:         20 * time.Millisecond,
	MaxAttempts: 4,
}

func TestBestEffortRetryEventuallySucceeds(t *testing.T) {
	// Apply fails on attempt 1 (in-graph), succeeds on the first
	// background retry attempt.
	var applyAttempts atomic.Int32
	retryCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	callbackCh := make(chan int, shortRetryPolicy.MaxAttempts+1)
	g := Graph{
		RetryCtx:    retryCtx,
		RetryPolicy: shortRetryPolicy,
		RetryCallback: func(name string, attempt int, err error) {
			callbackCh <- attempt
		},
		Components: []Component{{
			Name: "flaky",
			Apply: func(_ context.Context) error {
				n := applyAttempts.Add(1)
				if n == 1 {
					return errors.New("first-fail")
				}
				return nil
			},
			BestEffort: true,
		}},
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Wait for the retry callback (retry succeeds on attempt 1).
	select {
	case attempt := <-callbackCh:
		if attempt != 1 {
			t.Errorf("first callback attempt = %d, want 1", attempt)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retry callback never fired")
	}
	if got := applyAttempts.Load(); got != 2 {
		t.Errorf("Apply invocation count = %d, want 2 (1 in-graph + 1 retry)", got)
	}
}

func TestBestEffortRetryExhausts(t *testing.T) {
	// Apply always fails — retry loop should exhaust MaxAttempts
	// and stop calling.
	var applyAttempts atomic.Int32
	retryCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	var lastAttempt atomic.Int32
	g := Graph{
		RetryCtx:    retryCtx,
		RetryPolicy: shortRetryPolicy,
		RetryCallback: func(name string, attempt int, err error) {
			lastAttempt.Store(int32(attempt))
			if attempt == shortRetryPolicy.MaxAttempts {
				close(done)
			}
		},
		Components: []Component{{
			Name: "broken",
			Apply: func(_ context.Context) error {
				applyAttempts.Add(1)
				return errors.New("permanent")
			},
			BestEffort: true,
		}},
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop did not exhaust MaxAttempts")
	}
	// Give the loop a beat to exit; then verify no further attempts.
	time.Sleep(50 * time.Millisecond)
	if got := lastAttempt.Load(); int(got) != shortRetryPolicy.MaxAttempts {
		t.Errorf("last callback attempt = %d, want %d",
			got, shortRetryPolicy.MaxAttempts)
	}
	// applyAttempts = 1 in-graph + MaxAttempts retries.
	wantApplies := int32(1 + shortRetryPolicy.MaxAttempts)
	if got := applyAttempts.Load(); got != wantApplies {
		t.Errorf("Apply invocations = %d, want %d", got, wantApplies)
	}
}

func TestBestEffortRetryStopsOnRetryCtxCancel(t *testing.T) {
	// A permanent failure would exhaust MaxAttempts normally.
	// Cancelling retryCtx after the first retry should abort the
	// loop before it uses all attempts.
	retryCtx, cancelRetry := context.WithCancel(context.Background())
	var applyAttempts atomic.Int32
	callbacks := make(chan int, 16)
	g := Graph{
		RetryCtx:    retryCtx,
		RetryPolicy: shortRetryPolicy,
		RetryCallback: func(name string, attempt int, err error) {
			callbacks <- attempt
		},
		Components: []Component{{
			Name: "cancelled",
			Apply: func(c context.Context) error {
				applyAttempts.Add(1)
				return errors.New("still failing")
			},
			BestEffort: true,
		}},
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Wait for the first retry to fire, then cancel.
	select {
	case <-callbacks:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first retry never fired")
	}
	cancelRetry()
	// Drain any in-flight callback that raced the cancel.
	drainDone := time.After(200 * time.Millisecond)
	for {
		select {
		case <-callbacks:
		case <-drainDone:
			// Retry should have stopped well short of MaxAttempts.
			total := applyAttempts.Load()
			maxBudget := int32(1 + shortRetryPolicy.MaxAttempts)
			if total >= maxBudget {
				t.Errorf("retry loop did not stop on cancel: attempts=%d (budget=%d)",
					total, maxBudget)
			}
			return
		}
	}
}

func TestBestEffortWithoutRetryCtxIsOneShot(t *testing.T) {
	// With RetryCtx=nil (the default), a failing BestEffort component
	// must NOT be retried in the background.
	var applyAttempts atomic.Int32
	g := Graph{
		Components: []Component{{
			Name: "one-shot",
			Apply: func(_ context.Context) error {
				applyAttempts.Add(1)
				return errors.New("fail")
			},
			BestEffort: true,
		}},
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Give a background loop a chance to fire if it existed.
	time.Sleep(50 * time.Millisecond)
	if got := applyAttempts.Load(); got != 1 {
		t.Errorf("Apply invocations = %d, want 1 (no retries without RetryCtx)", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A slow Ready must not hold a MaxParallel slot. Longhorn's Ready can
// run for ten minutes; if the slot covered it, one slow component would
// stall every queued peer and capping concurrency would be unusable.
func TestMaxParallelBoundsApplyNotReady(t *testing.T) {
	const n = 4
	var mu sync.Mutex
	applyInFlight, applyPeak := 0, 0
	readyInFlight, readyPeak := 0, 0

	releaseReady := make(chan struct{})
	var comps []Component
	for i := 0; i < n; i++ {
		comps = append(comps, Component{
			Name: fmt.Sprintf("c%d", i),
			Apply: func(context.Context) error {
				mu.Lock()
				applyInFlight++
				applyPeak = max(applyPeak, applyInFlight)
				mu.Unlock()
				time.Sleep(30 * time.Millisecond)
				mu.Lock()
				applyInFlight--
				mu.Unlock()
				return nil
			},
			Ready: func(context.Context) error {
				mu.Lock()
				readyInFlight++
				readyPeak = max(readyPeak, readyInFlight)
				mu.Unlock()
				<-releaseReady // stand in for a long convergence wait
				mu.Lock()
				readyInFlight--
				mu.Unlock()
				return nil
			},
		})
	}

	g := Graph{Components: comps, MaxParallel: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	// Every component must reach Ready even though only 2 may Apply at
	// once — that only happens if the slot is freed before Ready.
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		got := readyInFlight
		mu.Unlock()
		if got == n {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d/%d components reached Ready; a Ready wait is holding a slot", got, n)
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(releaseReady)
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if applyPeak > 2 {
		t.Errorf("concurrent Apply peaked at %d, want <= MaxParallel (2)", applyPeak)
	}
	if readyPeak != n {
		t.Errorf("concurrent Ready peaked at %d, want %d (Ready must be unbounded)", readyPeak, n)
	}
}
