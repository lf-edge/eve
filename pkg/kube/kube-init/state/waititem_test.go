// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shadowWaitItems points WaitItemDir at a temp dir and shortens the
// poll so a held breakpoint is observable in a unit test.
func shadowWaitItems(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origDir, origPoll := WaitItemDir, waitItemPollInterval
	WaitItemDir = dir
	waitItemPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		WaitItemDir = origDir
		waitItemPollInterval = origPoll
	})
	return dir
}

// TestWaitForItemNoFileReturnsImmediately pins the normal case: every
// call site pays one stat and nothing else.
func TestWaitForItemNoFileReturnsImmediately(t *testing.T) {
	shadowWaitItems(t)
	done := make(chan struct{})
	go func() { WaitForItem(context.Background(), "longhorn"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForItem blocked with no breakpoint file present")
	}
}

// TestWaitForItemHoldsUntilFileRemoved is the feature itself.
func TestWaitForItemHoldsUntilFileRemoved(t *testing.T) {
	dir := shadowWaitItems(t)
	path := filepath.Join(dir, "wait_longhorn")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatalf("stage breakpoint: %v", err)
	}

	done := make(chan struct{})
	go func() { WaitForItem(context.Background(), "longhorn"); close(done) }()

	select {
	case <-done:
		t.Fatal("WaitForItem returned while the breakpoint file was present")
	case <-time.After(50 * time.Millisecond):
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("release breakpoint: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForItem did not resume after the file was removed")
	}
}

// TestWaitForItemReleasedByContext keeps SIGTERM working while a
// breakpoint is held — otherwise a forgotten file wedges shutdown.
func TestWaitForItemReleasedByContext(t *testing.T) {
	dir := shadowWaitItems(t)
	if err := os.WriteFile(filepath.Join(dir, "wait_wait"), nil, 0644); err != nil {
		t.Fatalf("stage breakpoint: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { WaitForItem(ctx, "wait"); close(done) }()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForItem ignored context cancellation")
	}
}

// TestWaitForItemNamesAreScoped guards against one breakpoint holding
// a different component.
func TestWaitForItemNamesAreScoped(t *testing.T) {
	dir := shadowWaitItems(t)
	if err := os.WriteFile(filepath.Join(dir, "wait_longhorn"), nil, 0644); err != nil {
		t.Fatalf("stage breakpoint: %v", err)
	}
	done := make(chan struct{})
	go func() { WaitForItem(context.Background(), "kubevirt"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wait_longhorn held the kubevirt breakpoint")
	}
}
