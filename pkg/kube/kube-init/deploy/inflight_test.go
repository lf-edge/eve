// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"testing"
	"time"
)

func shortenQuiescencePoll(t *testing.T) {
	t.Helper()
	old := quiescencePollInterval
	quiescencePollInterval = 2 * time.Millisecond
	t.Cleanup(func() { quiescencePollInterval = old })
}

// A nil tracker must be usable — callers that do not care leave the
// Graph field unset, and every call site would otherwise need a guard.
func TestRetryTrackerNilIsQuiescent(t *testing.T) {
	var tr *RetryTracker
	tr.add()
	tr.done()
	if n := tr.InFlight(); n != 0 {
		t.Fatalf("nil tracker reported %d in flight", n)
	}
	if err := tr.AwaitQuiescent(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("nil tracker not quiescent: %v", err)
	}
}

func TestRetryTrackerAwaitReturnsWhenLastRetryFinishes(t *testing.T) {
	shortenQuiescencePoll(t)
	tr := &RetryTracker{}
	tr.add()
	tr.add()
	time.AfterFunc(10*time.Millisecond, tr.done)
	time.AfterFunc(20*time.Millisecond, tr.done)

	if err := tr.AwaitQuiescent(context.Background(), time.Second); err != nil {
		t.Fatalf("want quiescence once both finished, got %v", err)
	}
	if n := tr.InFlight(); n != 0 {
		t.Fatalf("in flight = %d after both done", n)
	}
}

// The budget must expire rather than block forever — a wedged component
// cannot be allowed to hold up the snapshot.
func TestRetryTrackerAwaitGivesUpAndNamesTheCount(t *testing.T) {
	shortenQuiescencePoll(t)
	tr := &RetryTracker{}
	tr.add()
	tr.add()
	err := tr.AwaitQuiescent(context.Background(), 20*time.Millisecond)
	if err == nil {
		t.Fatal("want an error when retries are still in flight")
	}
	if got := err.Error(); got == "" || !contains(got, "2 best-effort retries") {
		t.Fatalf("error should name the outstanding count, got %q", got)
	}
}

// done() must not underflow past zero — a double-done would otherwise
// make a later real retry look quiescent.
func TestRetryTrackerDoesNotUnderflow(t *testing.T) {
	tr := &RetryTracker{}
	tr.done()
	tr.done()
	tr.add()
	if n := tr.InFlight(); n != 1 {
		t.Fatalf("in flight = %d, want 1", n)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
