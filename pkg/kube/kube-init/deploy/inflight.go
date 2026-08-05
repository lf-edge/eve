// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RetryTracker counts the BestEffort retry loops currently running.
//
// A returned graph run does not mean nothing is still working: BestEffort
// lets the run complete while a component converges in the background. A
// caller about to do something destructive — stopping k3s and every image
// pull under it — needs to know work is outstanding.
//
// The zero value is usable, and a nil *RetryTracker reports nothing in
// flight, so callers that do not care can leave the field unset.
type RetryTracker struct {
	mu sync.Mutex
	n  int
}

func (t *RetryTracker) add() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.n++
	t.mu.Unlock()
}

func (t *RetryTracker) done() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.n > 0 {
		t.n--
	}
	t.mu.Unlock()
}

// InFlight reports how many BestEffort retry loops are running.
func (t *RetryTracker) InFlight() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.n
}

// quiescencePollInterval is how often AwaitQuiescent rechecks. Retries
// finish on their own schedule; a coarse poll is enough and keeps this
// free of the channel bookkeeping a condition variable would need.
// A var only so tests can shorten it.
var quiescencePollInterval = 2 * time.Second

// AwaitQuiescent blocks until no BestEffort retry is in flight, at most
// for budget. It reports an error naming the outstanding count if the
// budget expires — callers are expected to log that and proceed rather
// than block forever, since a genuinely wedged component must never
// hold up the state machine.
func (t *RetryTracker) AwaitQuiescent(ctx context.Context, budget time.Duration) error {
	if t.InFlight() == 0 {
		return nil
	}
	deadline := time.Now().Add(budget)
	tick := time.NewTicker(quiescencePollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if n := t.InFlight(); n == 0 {
				return nil
			} else if time.Now().After(deadline) {
				return fmt.Errorf("%d best-effort retr%s still in flight after %s",
					n, plural(n), budget.Round(time.Second))
			}
		}
	}
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
