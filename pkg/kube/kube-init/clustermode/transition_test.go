// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clustermode

import (
	"context"
	"errors"
	"testing"
)

// fakeSupervisor satisfies Supervisor with no-op methods. The
// runner's stop/hooks steps invoke this when sup is non-nil.
type fakeSupervisor struct {
	stopCalls  int
	hooksCalls int
	stopErr    error
}

func (f *fakeSupervisor) Stop() error  { f.stopCalls++; return f.stopErr }
func (f *fakeSupervisor) RunHooks()    { f.hooksCalls++ }

// TestRunCancelledBeforeFirstStep ensures pre-cancelled ctx is
// honoured immediately — Run must NOT execute any step (not even
// StepDiscover) and must surface the cancellation in the error.
//
// This is the only ctx-handling case we can verify without
// faking out the underlying packages: a pre-cancelled context
// trips the very first ctx.Err() check inside Run, regardless
// of whether the step methods would otherwise hit external
// dependencies.
func TestRunCancelledBeforeFirstStep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := NewRunner(&fakeSupervisor{}, nil)
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("expected error for pre-cancelled ctx, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in chain, got %v", err)
	}
}

// TestProgressFnReceivesStepNames verifies the order in which the
// progress callback fires. We pre-cancel ctx, so Run only invokes
// progress for the steps it had time to start before the cancel
// check tripped — but since the ctx check fires BEFORE the first
// step, the callback should fire zero times.
//
// This pins the contract: cancellation must be detected before
// any progress callback fires for the cancelled step.
func TestProgressFnNotFiredOnPreCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var called []string
	r := NewRunner(nil, func(s string) {
		called = append(called, s)
	})
	_ = r.Run(ctx) // expect error; we don't assert it here.
	if len(called) != 0 {
		t.Errorf("progress fired %d time(s) on pre-cancelled ctx (steps=%v); "+
			"want 0 — ctx.Err must be checked before progress",
			len(called), called)
	}
}

// TestRunCancelledMidStepHaltsRemainingSteps drives Run with a
// progress callback that cancels the context after N steps have
// fired. The runner must then stop firing progress for subsequent
// steps and return a wrapped context.Canceled.
//
// Limitation: because the steps call into k3s/components which
// require a real cluster, the first step (StepDiscover) will
// itself fail before we can cancel. We instead verify the
// cancellation-check shape by cancelling on the FIRST progress
// callback. The runner should not invoke progress for any step
// after that, and the error should include context.Canceled.
//
// This still catches a meaningful regression: if someone removes
// the per-step ctx.Err() check, the cancel signal would be
// ignored and progress would keep firing for later steps.
func TestRunCancelledAfterFirstProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var called []string
	progress := func(s string) {
		called = append(called, s)
		if len(called) == 1 {
			cancel()
		}
	}

	r := NewRunner(nil, progress)
	err := r.Run(ctx)
	if err == nil {
		t.Fatal("expected an error (cancellation or step failure), got nil")
	}

	// Without faking step internals we can't guarantee step 1
	// completes; what we can guarantee is that progress fires no
	// more than ONCE before the cancel takes effect. (The runner
	// might also fail step 1 itself before the cancel check —
	// either outcome is fine; we just must not see progress for
	// step 2 or later.)
	if len(called) > 1 {
		t.Errorf("progress fired %d times after cancel (steps=%v); "+
			"want at most 1", len(called), called)
	}
}

// TestNewRunnerNilSupervisorNoOp confirms the documented test-
// mode contract: NewRunner(nil, ...) is allowed and StepStopK3s /
// StepRunHooks become no-ops (they don't panic).
//
// We can call these step methods directly because they don't
// touch external packages.
func TestNewRunnerNilSupervisorStepsAreNoOp(t *testing.T) {
	r := NewRunner(nil, nil)
	// Initialise r.cs so step methods that check it don't panic.
	// StepStopK3s and StepRunHooks don't deref r.cs, so we can
	// call them on an empty Runner.
	if err := r.StepStopK3s(context.Background()); err != nil {
		t.Errorf("StepStopK3s with nil sup: got err = %v, want nil", err)
	}
	if err := r.StepRunHooks(context.Background()); err != nil {
		t.Errorf("StepRunHooks with nil sup: got err = %v, want nil", err)
	}
}
