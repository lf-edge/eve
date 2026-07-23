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

func nop(_ context.Context) error { return nil }

func TestPlanEmptyGraph(t *testing.T) {
	waves, err := Graph{}.plan()
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if waves != nil {
		t.Errorf("waves = %v, want nil", waves)
	}
}

func TestPlanRejectsEmptyName(t *testing.T) {
	g := Graph{Nodes: []Node{{Name: "", Apply: nop}}}
	if _, err := g.plan(); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestPlanRejectsDuplicateName(t *testing.T) {
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: nop},
		{Name: "a", Apply: nop},
	}}
	_, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestPlanRejectsNilApply(t *testing.T) {
	g := Graph{Nodes: []Node{{Name: "a"}}}
	_, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "nil Apply") {
		t.Fatalf("expected nil-Apply error, got %v", err)
	}
}

func TestPlanRejectsUnknownDep(t *testing.T) {
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: nop, Deps: []string{"ghost"}},
	}}
	_, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected unknown-dep error, got %v", err)
	}
}

func TestPlanRejectsSelfDep(t *testing.T) {
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: nop, Deps: []string{"a"}},
	}}
	_, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("expected self-dep error, got %v", err)
	}
}

func TestPlanRejectsCycle(t *testing.T) {
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: nop, Deps: []string{"b"}},
		{Name: "b", Apply: nop, Deps: []string{"c"}},
		{Name: "c", Apply: nop, Deps: []string{"a"}},
	}}
	_, err := g.plan()
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestPlanWavesByDependency(t *testing.T) {
	// a, b are roots.
	// c depends on a; d depends on a + b; e depends on c + d.
	// Expected waves: [a b] -> [c d] -> [e]
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: nop},
		{Name: "b", Apply: nop},
		{Name: "c", Apply: nop, Deps: []string{"a"}},
		{Name: "d", Apply: nop, Deps: []string{"a", "b"}},
		{Name: "e", Apply: nop, Deps: []string{"c", "d"}},
	}}
	waves, err := g.plan()
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(waves) != 3 {
		t.Fatalf("got %d waves, want 3", len(waves))
	}
	want := [][]string{{"a", "b"}, {"c", "d"}, {"e"}}
	for i, w := range waves {
		var got []string
		for _, n := range w {
			got = append(got, n.Name)
		}
		if !equalStrings(got, want[i]) {
			t.Errorf("wave %d: got %v, want %v", i, got, want[i])
		}
	}
}

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
		Nodes: []Node{
			{Name: "a", Apply: record("a")},
			{Name: "b", Apply: record("b"), Deps: []string{"a"}},
			{Name: "c", Apply: record("c"), Deps: []string{"b"}},
		},
	}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !equalStrings(order, []string{"a", "b", "c"}) {
		t.Errorf("order = %v, want [a b c]", order)
	}
}

func TestRunPropagatesApplyError(t *testing.T) {
	want := errors.New("boom")
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: func(_ context.Context) error { return want }},
		{Name: "b", Apply: nop, Deps: []string{"a"}},
	}}
	err := g.Run(context.Background())
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want chain containing %v", err, want)
	}
	if !strings.Contains(err.Error(), `"a" apply`) {
		t.Errorf("err should mention node + step, got %v", err)
	}
}

func TestRunPropagatesWaitReadyError(t *testing.T) {
	want := errors.New("not ready")
	g := Graph{Nodes: []Node{
		{Name: "a", Apply: nop, WaitReady: func(_ context.Context) error { return want }},
	}}
	err := g.Run(context.Background())
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want chain containing %v", err, want)
	}
	if !strings.Contains(err.Error(), `"a" waitReady`) {
		t.Errorf("err should mention waitReady, got %v", err)
	}
}

func TestRunCancelsPeersOnFirstFailure(t *testing.T) {
	// Two independent nodes; one fails immediately, the other blocks
	// on ctx. The blocker must observe cancellation promptly.
	failing := errors.New("first")
	var blockerCancelled atomic.Bool
	g := Graph{Nodes: []Node{
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
	g := Graph{Nodes: []Node{
		{Name: "blocker", Apply: func(c context.Context) error {
			<-c.Done()
			return c.Err()
		}},
	}}
	cancelDone := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
		close(cancelDone)
	}()
	err := g.Run(ctx)
	<-cancelDone
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled in chain", err)
	}
}

func TestBestEffortApplyFailureNotPropagated(t *testing.T) {
	want := errors.New("optional component down")
	g := Graph{Nodes: []Node{
		{Name: "opt", Apply: func(_ context.Context) error { return want },
			BestEffort: true},
		{Name: "downstream", Apply: nop, Deps: []string{"opt"}},
	}}
	if err := g.Run(context.Background()); err != nil {
		t.Errorf("BestEffort apply failure should not propagate, got %v", err)
	}
}

func TestBestEffortWaitReadyTimeoutSurfacesAsSuccess(t *testing.T) {
	var waitReadyEnteredAt time.Time
	g := Graph{Nodes: []Node{
		{
			Name:  "slow",
			Apply: nop,
			WaitReady: func(c context.Context) error {
				waitReadyEnteredAt = time.Now()
				<-c.Done()
				return c.Err()
			},
			BestEffort:                 true,
			BestEffortWaitReadyTimeout: 50 * time.Millisecond,
		},
	}}
	start := time.Now()
	err := g.Run(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("BestEffort timeout should not propagate, got %v", err)
	}
	if waitReadyEnteredAt.IsZero() {
		t.Fatal("WaitReady was never called")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("BestEffort wait took %v; should be bounded near 50ms", elapsed)
	}
}

func TestBestEffortWaitReadyTimeoutDefaultsApplied(t *testing.T) {
	// Leaving BestEffortWaitReadyTimeout at zero must still bound
	// the wait. We can't wait the full default in a unit test, but
	// we can verify the default value is non-zero.
	if defaultBestEffortWaitReadyTimeout <= 0 {
		t.Errorf("defaultBestEffortWaitReadyTimeout = %v, want > 0",
			defaultBestEffortWaitReadyTimeout)
	}
}

func TestNonBestEffortWaitReadyNotBounded(t *testing.T) {
	// Sanity: a non-BestEffort wait runs under the caller's ctx,
	// not a derived sub-context. We verify by giving the caller's
	// ctx a tight deadline and checking the error chains to it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	g := Graph{Nodes: []Node{
		{Name: "slow", Apply: nop, WaitReady: func(c context.Context) error {
			<-c.Done()
			return c.Err()
		}},
	}}
	err := g.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

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
	nodes := make([]Node, N)
	for i := range nodes {
		nodes[i] = Node{Name: fmt.Sprintf("n%d", i), Apply: apply}
	}
	g := Graph{Nodes: nodes, MaxParallel: 2}
	if err := g.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if peak > 2 {
		t.Errorf("peak in-flight = %d, want <= 2", peak)
	}
}

func TestRunReportsAllErrorsAlphabetically(t *testing.T) {
	errA := errors.New("a failed")
	errC := errors.New("c failed")
	g := Graph{Nodes: []Node{
		{Name: "z", Apply: nop},
		{Name: "c", Apply: func(_ context.Context) error { return errC }},
		{Name: "a", Apply: func(_ context.Context) error { return errA }},
	}}
	err := g.Run(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// "a" should be the head (alphabetical), "c" should appear in the
	// "(also: ...)" suffix.
	if !errors.Is(err, errA) {
		t.Errorf("head error = %v, want chain containing %v", err, errA)
	}
	if !strings.Contains(err.Error(), `"c"`) {
		t.Errorf("err should mention secondary failure 'c': %v", err)
	}
}

func TestWaitReadyOnlyRunsWhenApplySucceeds(t *testing.T) {
	var waitCalled atomic.Bool
	g := Graph{Nodes: []Node{
		{
			Name:  "a",
			Apply: func(_ context.Context) error { return errors.New("apply failed") },
			WaitReady: func(_ context.Context) error {
				waitCalled.Store(true)
				return nil
			},
		},
	}}
	_ = g.Run(context.Background())
	if waitCalled.Load() {
		t.Error("WaitReady should not run when Apply fails")
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
