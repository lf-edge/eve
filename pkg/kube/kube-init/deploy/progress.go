// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Sentinels distinguishing the two ways a progress-guarded Ready can
// be given up on. Callers log them differently: a stall is actionable,
// hitting the ceiling means the component reports work but never
// converges.
var (
	// ErrNoProgress means Ready was cancelled because its Progress
	// token stopped changing for the whole ReadyTimeout window.
	ErrNoProgress = errors.New("no progress")

	// ErrReadyCeiling means Ready kept reporting progress but never
	// returned within ReadyCeiling.
	ErrReadyCeiling = errors.New("ready ceiling exceeded")
)

// defaultReadyCeilingFactor multiplies ReadyTimeout to derive
// ReadyCeiling when a Component leaves it zero.
const defaultReadyCeilingFactor = 3

// Vars, not consts, only so tests can shorten them — the same reason
// defaultRetryPolicy is a var. Production code must not mutate them.
var (
	// progressPollInterval is how often a guarded Ready samples its
	// Progress token. The probe hits containerd, which is already busy
	// pulling, so it must not be tight.
	progressPollInterval = 15 * time.Second

	// readyDrainGrace bounds the wait for a cancelled Ready to return.
	// One that ignores its ctx must not wedge the graph.
	readyDrainGrace = 30 * time.Second

	// progressLogInterval throttles the token log; during a download the
	// token moves every poll.
	progressLogInterval = 60 * time.Second
)

// runReadyGuarded runs c.Ready under the right deadline semantics.
//
// Without Progress this is the plain wall-clock timeout. With Progress
// the timeout becomes a no-progress deadline: it restarts whenever the
// token changes, so a slow-but-advancing component is left alone and
// only a genuinely stalled one is cancelled. ReadyCeiling still bounds
// the total.
//
// readyTimeout is the already-defaulted budget; zero means "no bound"
// and the caller's ctx governs.
func runReadyGuarded(ctx context.Context, c *Component, readyTimeout time.Duration) error {
	if c.Progress == nil {
		readyCtx := ctx
		if readyTimeout > 0 {
			var cancel context.CancelFunc
			readyCtx, cancel = context.WithTimeout(ctx, readyTimeout)
			defer cancel()
		}
		return c.Ready(readyCtx)
	}

	ceiling := c.ReadyCeiling
	if ceiling <= 0 {
		ceiling = defaultReadyCeilingFactor * readyTimeout
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Ready(runCtx) }()

	// Abandoning a cancelled Ready leaks its goroutine until it
	// notices ctx; bounded so the graph is never held by one that
	// does not.
	giveUp := func(err error) error {
		cancel()
		select {
		case <-done:
		case <-time.After(readyDrainGrace):
		}
		return err
	}

	began := time.Now()
	lastProgress := began
	lastToken := ""
	haveToken := false
	lastLogged := time.Time{}
	quietWarned := false

	tick := time.NewTicker(progressPollInterval)
	defer tick.Stop()

	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			// A probe error is "unknown", not "stalled" — it must not
			// reset the timer, or a permanently broken probe would
			// make the deadline unreachable.
			if tok, err := c.Progress(runCtx); err == nil {
				if !haveToken || tok != lastToken {
					if quietWarned {
						log.Printf("deploy: %s: progress resumed after %s: %s",
							c.Name, time.Since(lastProgress).Round(time.Second), tok)
					} else if time.Since(lastLogged) >= progressLogInterval {
						log.Printf("deploy: %s: progress %s", c.Name, tok)
						lastLogged = time.Now()
					}
					lastToken, haveToken = tok, true
					lastProgress = time.Now()
					quietWarned = false
				}
			}
			// Once, halfway to the deadline: the frozen token names what
			// the probe was watching when the component stopped moving.
			if quiet := time.Since(lastProgress); !quietWarned && quiet >= readyTimeout/2 {
				log.Printf("deploy: %s: no progress for %s, token held at: %s",
					c.Name, quiet.Round(time.Second), lastToken)
				quietWarned = true
			}
			if since := time.Since(lastProgress); since >= readyTimeout {
				return giveUp(fmt.Errorf("%w for %s: %w",
					ErrNoProgress, since.Round(time.Second), context.DeadlineExceeded))
			}
			if total := time.Since(began); total >= ceiling {
				return giveUp(fmt.Errorf("%w after %s: %w",
					ErrReadyCeiling, total.Round(time.Second), context.DeadlineExceeded))
			}
		}
	}
}
