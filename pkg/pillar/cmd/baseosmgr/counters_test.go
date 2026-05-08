// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"os"
	"strings"
	"testing"
)

func TestSaveAndReadCurrentRetryUpdateCounter(t *testing.T) {
	tc := newTestCtx(t)
	// Absent file → 0.
	if got := readSavedCurrentRetryUpdateCounter(tc.ctx); got != 0 {
		t.Fatalf("expected 0 for absent, got %d", got)
	}

	tc.ctx.currentUpdateRetry = 42
	saveCurrentRetryUpdateCounter(tc.ctx)

	if got := readSavedCurrentRetryUpdateCounter(tc.ctx); got != 42 {
		t.Fatalf("expected 42 after save, got %d", got)
	}

	// Verify the file is also human-readable: WriteRename writes the
	// decimal text the production code uses.
	b, err := os.ReadFile(tc.ctx.paths.currentRetryUpdateCounter)
	if err != nil {
		t.Fatalf("read counter file: %v", err)
	}
	if got := strings.TrimSpace(string(b)); got != "42" {
		t.Fatalf("file %q want %q", got, "42")
	}
}

func TestSaveAndReadConfigRetryUpdateCounter(t *testing.T) {
	tc := newTestCtx(t)
	if got := readSavedConfigRetryUpdateCounter(tc.ctx); got != 0 {
		t.Fatalf("expected 0 for absent, got %d", got)
	}

	tc.ctx.configUpdateRetry = 11
	saveConfigRetryUpdateCounter(tc.ctx)

	if got := readSavedConfigRetryUpdateCounter(tc.ctx); got != 11 {
		t.Fatalf("expected 11 after save, got %d", got)
	}
}

func TestReadSavedCurrentRetryUpdateCounter_GarbageReturnsZero(t *testing.T) {
	tc := newTestCtx(t)
	if err := os.WriteFile(tc.ctx.paths.currentRetryUpdateCounter,
		[]byte("not-a-number"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if got := readSavedCurrentRetryUpdateCounter(tc.ctx); got != 0 {
		t.Fatalf("expected 0 for garbage, got %d", got)
	}
}

func TestSaveCurrentRetryUpdateCounter_OverwritesExisting(t *testing.T) {
	tc := newTestCtx(t)
	tc.ctx.currentUpdateRetry = 1
	saveCurrentRetryUpdateCounter(tc.ctx)
	tc.ctx.currentUpdateRetry = 9
	saveCurrentRetryUpdateCounter(tc.ctx)
	if got := readSavedCurrentRetryUpdateCounter(tc.ctx); got != 9 {
		t.Fatalf("expected overwrite to 9, got %d", got)
	}
}
