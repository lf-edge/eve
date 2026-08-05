// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"log"
	"math/rand"
	"time"
)

// spawnBestEffortRetry runs c.Apply then c.Ready under retryCtx with exponential backoff.
// retryCtx must outlive Run so retries survive workCtx cancellation.
// A nil retryCtx is a no-op.
func spawnBestEffortRetry(
	retryCtx context.Context,
	c *Component,
	policy RetryPolicy,
	callback RetryCallback,
	bus *Bus,
	retries *RetryTracker,
	firstErr error,
	firstStep string,
) {
	if retryCtx == nil {
		return
	}
	policy = policy.withDefaults()
	// Registered before the goroutine is scheduled: a caller that
	// checks quiescence immediately after Run returns must not see
	// zero because the loop has not been scheduled yet.
	retries.add()
	go retryLoop(retryCtx, c, policy, callback, bus, retries, firstErr, firstStep)
}

// retryLoop is the runnable body of the retry goroutine.
func retryLoop(
	retryCtx context.Context,
	c *Component,
	policy RetryPolicy,
	callback RetryCallback,
	bus *Bus,
	retries *RetryTracker,
	firstErr error,
	firstStep string,
) {
	defer retries.done()
	log.Printf("deploy: %s: BEST-EFFORT retry scheduled after %s failure: %v",
		c.Name, firstStep, firstErr)

	backoff := policy.Initial
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		// Sleep first (initial delay applies before attempt 1);
		// exponential + jitter capped at policy.Cap. Jitter is
		// [0, backoff/2) — bounds the sleep in [backoff, 1.5*backoff)
		// and prevents thundering herd if multiple components all
		// hit the same slow API window.
		jitter := time.Duration(rng.Int63n(int64(backoff/2 + 1)))
		sleep := backoff + jitter
		select {
		case <-retryCtx.Done():
			log.Printf("deploy: %s: BEST-EFFORT retry abandoned (ctx cancelled during sleep, attempt %d/%d)",
				c.Name, attempt, policy.MaxAttempts)
			return
		case <-time.After(sleep):
		}

		// Bound this attempt's Ready by ReadyTimeout so a wedged
		// Ready doesn't hold the retry loop indefinitely.
		attemptCtx := retryCtx
		var cancel context.CancelFunc
		readyTimeout := c.ReadyTimeout
		if readyTimeout <= 0 {
			readyTimeout = defaultReadyTimeout
		}
		// With Progress set, readyTimeout is a no-progress window and the
		// real bound is the ceiling; sizing this ctx off the window would
		// cancel an advancing pull and lose its in-flight layer.
		attemptBound := readyTimeout
		if c.Progress != nil {
			attemptBound = c.ReadyCeiling
			if attemptBound <= 0 {
				attemptBound = defaultReadyCeilingFactor * readyTimeout
			}
		}
		attemptCtx, cancel = context.WithTimeout(retryCtx, attemptBound+policy.Cap)
		err := runApplyThenReady(attemptCtx, c, readyTimeout)
		cancel()

		if callback != nil {
			callback(c.Name, attempt, err)
		}

		if err == nil {
			log.Printf("deploy: %s: BEST-EFFORT retry SUCCEEDED on attempt %d/%d",
				c.Name, attempt, policy.MaxAttempts)
			// The condition holds now, so publish it. Without this a
			// component that missed its in-graph Ready window but
			// converged on retry would leave its signal unset forever:
			// the status socket would under-report a healthy component,
			// and an out-of-graph consumer would await it indefinitely.
			if bus != nil {
				for _, sig := range c.Emits {
					bus.Emit(sig)
				}
			}
			return
		}

		log.Printf("deploy: %s: BEST-EFFORT retry attempt %d/%d FAILED: %v",
			c.Name, attempt, policy.MaxAttempts, err)

		// Advance backoff for next iteration.
		backoff = time.Duration(float64(backoff) * policy.Factor)
		if backoff > policy.Cap {
			backoff = policy.Cap
		}

		// Honour cancel between attempts too — the sleep above
		// already checks ctx, but retryCtx may cancel while the
		// attempt itself is running. In that case attemptCtx would
		// have surfaced ctx.Err via `err`, and we'd re-loop, sleep,
		// and observe ctx.Done. Fast-path exit here saves that
		// extra iteration.
		if retryCtx.Err() != nil {
			log.Printf("deploy: %s: BEST-EFFORT retry abandoned (ctx cancelled between attempts, attempt %d/%d)",
				c.Name, attempt, policy.MaxAttempts)
			return
		}
	}
	log.Printf("deploy: %s: BEST-EFFORT retry EXHAUSTED after %d attempts",
		c.Name, policy.MaxAttempts)
}

// runApplyThenReady is the retry-loop's per-attempt worker. Runs
// Apply and (if defined and Apply succeeded) Ready. The Ready call
// is bounded by readyTimeout.
//
// Returns nil on success (both Apply and Ready satisfied) or the
// first non-nil step error.
func runApplyThenReady(ctx context.Context, c *Component, readyTimeout time.Duration) error {
	if c.Apply != nil {
		if err := c.Apply(ctx); err != nil {
			return err
		}
	}
	if c.Ready == nil {
		return nil
	}
	// DeadlineExceeded stays distinguishable via errors.Is so the caller
	// can tell "Ready is still converging" from "Apply produced a
	// permanent error"; today the retry loop treats both the same
	// (schedule another attempt), but a future refinement could shortcut
	// permanent errors.
	return runReadyGuarded(ctx, c, readyTimeout)
}
