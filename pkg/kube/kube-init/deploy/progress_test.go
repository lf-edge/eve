// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// shortenPolls makes the progress machinery run on a millisecond scale
// for tests and restores the production values afterwards.
func shortenPolls(t *testing.T) {
	t.Helper()
	poll, drain := progressPollInterval, readyDrainGrace
	progressPollInterval = 2 * time.Millisecond
	readyDrainGrace = 200 * time.Millisecond
	t.Cleanup(func() {
		progressPollInterval, readyDrainGrace = poll, drain
	})
}

// blockingReady never returns until its ctx is cancelled — the shape of
// a Ready waiting on a component that has not converged.
func blockingReady(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// A component whose Progress never changes is stalled and must be given
// up on, so the caller can retry. This is the case where cancelling
// costs nothing.
func TestRunReadyGuardedGivesUpWhenProgressStops(t *testing.T) {
	shortenPolls(t)
	c := &Component{
		Name:         "stuck",
		Ready:        blockingReady,
		Progress:     func(context.Context) (string, error) { return "frozen", nil },
		ReadyCeiling: 5 * time.Second,
	}
	err := runReadyGuarded(context.Background(), c, 30*time.Millisecond)
	if !errors.Is(err, ErrNoProgress) {
		t.Fatalf("want ErrNoProgress, got %v", err)
	}
	// Callers (and the existing BestEffort log branch) test for this.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the error to wrap DeadlineExceeded, got %v", err)
	}
}

// The regression this whole change exists for: a component that is slow
// but advancing must NOT be cancelled just because it outran the
// window. Ready here finishes long after the no-progress budget.
func TestRunReadyGuardedToleratesSlowButAdvancing(t *testing.T) {
	shortenPolls(t)
	var n atomic.Int64
	done := make(chan struct{})
	c := &Component{
		Name: "pulling",
		Ready: func(ctx context.Context) error {
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		// Every probe reports more bytes, as containerd does mid-pull.
		Progress: func(context.Context) (string, error) {
			return fmt.Sprintf("%d", n.Add(1)), nil
		},
		ReadyCeiling: 5 * time.Second,
	}
	// Complete well past the 20ms no-progress window.
	time.AfterFunc(150*time.Millisecond, func() { close(done) })

	if err := runReadyGuarded(context.Background(), c, 20*time.Millisecond); err != nil {
		t.Fatalf("advancing component was cancelled: %v", err)
	}
}

// Progress that advances forever without Ready ever returning must
// still terminate, or a component could hold the graph indefinitely.
func TestRunReadyGuardedEnforcesCeiling(t *testing.T) {
	shortenPolls(t)
	var n atomic.Int64
	c := &Component{
		Name:  "never-ready",
		Ready: blockingReady,
		Progress: func(context.Context) (string, error) {
			return fmt.Sprintf("%d", n.Add(1)), nil
		},
		ReadyCeiling: 60 * time.Millisecond,
	}
	err := runReadyGuarded(context.Background(), c, 30*time.Second)
	if !errors.Is(err, ErrReadyCeiling) {
		t.Fatalf("want ErrReadyCeiling, got %v", err)
	}
}

// A probe that always errors is "progress unknown" and must not reset
// the timer — otherwise a broken probe would make the deadline
// unreachable and restore the unbounded-wait behaviour.
func TestRunReadyGuardedProbeErrorDoesNotResetTimer(t *testing.T) {
	shortenPolls(t)
	c := &Component{
		Name:     "probe-broken",
		Ready:    blockingReady,
		Progress: func(context.Context) (string, error) { return "", errors.New("containerd down") },
	}
	err := runReadyGuarded(context.Background(), c, 30*time.Millisecond)
	if !errors.Is(err, ErrNoProgress) {
		t.Fatalf("want ErrNoProgress, got %v", err)
	}
}

// Without Progress the behaviour is unchanged: a plain wall clock.
func TestRunReadyGuardedWithoutProgressUsesWallClock(t *testing.T) {
	shortenPolls(t)
	c := &Component{Name: "plain", Ready: blockingReady}
	err := runReadyGuarded(context.Background(), c, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if errors.Is(err, ErrNoProgress) {
		t.Fatal("plain timeout must not be reported as a stall")
	}
}

// Caller cancellation still wins over both deadlines.
func TestRunReadyGuardedHonoursCallerCancel(t *testing.T) {
	shortenPolls(t)
	ctx, cancel := context.WithCancel(context.Background())
	var n atomic.Int64
	c := &Component{
		Name:     "cancelled",
		Ready:    blockingReady,
		Progress: func(context.Context) (string, error) { return fmt.Sprintf("%d", n.Add(1)), nil },
	}
	time.AfterFunc(20*time.Millisecond, cancel)
	if err := runReadyGuarded(ctx, c, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v", err)
	}
}
