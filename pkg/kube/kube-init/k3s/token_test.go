// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shadowK3sBinary points K3sSymlink at a guaranteed-missing path so
// the rotate exec fails deterministically across dev workstations
// (where /usr/bin/k3s may or may not exist).
func shadowK3sBinary(t *testing.T) {
	t.Helper()
	orig := K3sSymlink
	K3sSymlink = filepath.Join(t.TempDir(), "no-such-k3s")
	t.Cleanup(func() { K3sSymlink = orig })
}

// shadowTokenFile points k3sTokenFile at a fresh tmp path. Returns
// the path so tests can seed it.
func shadowTokenFile(t *testing.T) string {
	t.Helper()
	orig := k3sTokenFile
	p := filepath.Join(t.TempDir(), "k3s-token")
	k3sTokenFile = p
	t.Cleanup(func() { k3sTokenFile = orig })
	return p
}

// shrinkPollIntervals slashes the production poll cadences so tests
// finish in milliseconds rather than seconds.
func shrinkPollIntervals(t *testing.T) {
	t.Helper()
	origP, origB, origR := tokenPollInterval, bootstrapTokenPollInterval, tokenRotateRetryTimeout
	tokenPollInterval = 10 * time.Millisecond
	bootstrapTokenPollInterval = 10 * time.Millisecond
	tokenRotateRetryTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		tokenPollInterval = origP
		bootstrapTokenPollInterval = origB
		tokenRotateRetryTimeout = origR
	})
}

func TestRotateToNewTokenRejectsEmpty(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- RotateToNewToken(context.Background(), "") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for empty token, got nil")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("RotateToNewToken did not return promptly on empty token")
	}
}

func TestRotateToNewTokenCancellation(t *testing.T) {
	shadowK3sBinary(t)
	shadowTokenFile(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := RotateToNewToken(ctx, "tok")
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestRotateToNewTokenSucceedsWhenFileContainsNewToken(t *testing.T) {
	shadowK3sBinary(t)
	tokenPath := shadowTokenFile(t)
	if err := os.WriteFile(tokenPath, []byte("server:tok"), 0644); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if err := RotateToNewToken(context.Background(), "tok"); err != nil {
		t.Errorf("expected immediate success, got %v", err)
	}
}

func TestRotateTokenMissingCurrentTokenFails(t *testing.T) {
	shadowK3sBinary(t)
	shadowTokenFile(t)
	err := RotateToken(context.Background())
	if err == nil {
		t.Fatal("expected error reading missing token file, got nil")
	}
}

func TestRotateTokenSucceedsWhenFileChanges(t *testing.T) {
	shadowK3sBinary(t)
	shrinkPollIntervals(t)
	tokenPath := shadowTokenFile(t)
	if err := os.WriteFile(tokenPath, []byte("old-token"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	go func() {
		// Simulate k3s rewriting the file after a brief delay. The
		// actual rotate exec is bound to a missing binary, so the
		// poll loop is what we're testing: it must detect the change.
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(tokenPath, []byte("new-token"), 0644)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := RotateToken(ctx); err != nil {
		t.Errorf("expected success once file changes, got %v", err)
	}
}
