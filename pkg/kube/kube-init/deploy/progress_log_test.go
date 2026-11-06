// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

// captureLog redirects the standard logger for the duration of a test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	out, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(out); log.SetFlags(flags) })
	return &buf
}

// The whole point of the quiet announcement is to name the value the probe
// froze on. Without it a stall can only be inferred, and the missing signal has
// to be guessed at — which is what made the previous two diagnoses wrong.
func TestQuietPeriodNamesTheFrozenToken(t *testing.T) {
	shortenPolls(t)
	buf := captureLog(t)

	c := &Component{
		Name:         "wedged",
		Ready:        blockingReady,
		Progress:     func(context.Context) (string, error) { return "im=1[node-a:pending]", nil },
		ReadyCeiling: 5 * time.Second,
	}
	_ = runReadyGuarded(context.Background(), c, 60*time.Millisecond)

	got := buf.String()
	if !strings.Contains(got, "token held at: im=1[node-a:pending]") {
		t.Fatalf("quiet announcement missing the frozen token; log was:\n%s", got)
	}
	if n := strings.Count(got, "token held at:"); n != 1 {
		t.Fatalf("quiet announcement should fire once, fired %d times:\n%s", n, got)
	}
}

// A component that is merely slow must not produce the quiet announcement —
// otherwise the line stops meaning anything and the next investigation is back
// to guessing.
func TestNoQuietAnnouncementWhileAdvancing(t *testing.T) {
	shortenPolls(t)
	buf := captureLog(t)

	done := make(chan struct{})
	n := 0
	c := &Component{
		Name: "advancing",
		Ready: func(ctx context.Context) error {
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		Progress: func(context.Context) (string, error) {
			n++
			return string(rune('a' + n%26)), nil
		},
		ReadyCeiling: 5 * time.Second,
	}
	time.AfterFunc(120*time.Millisecond, func() { close(done) })

	if err := runReadyGuarded(context.Background(), c, 60*time.Millisecond); err != nil {
		t.Fatalf("advancing component failed: %v", err)
	}
	if got := buf.String(); strings.Contains(got, "token held at:") {
		t.Fatalf("quiet announcement fired while progressing:\n%s", got)
	}
}
