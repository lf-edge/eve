// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"os"
	"strings"
	"testing"
)

func TestForceFallbackCounter_ReadAbsent(t *testing.T) {
	tc := newTestCtx(t)
	got, found := readForceFallbackCounter(tc.ctx)
	if found {
		t.Fatalf("expected found=false for absent file (got %d)", got)
	}
}

func TestForceFallbackCounter_WriteThenRead(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 7)
	got, found := readForceFallbackCounter(tc.ctx)
	if !found {
		t.Fatal("expected found=true after write")
	}
	if got != 7 {
		t.Fatalf("got %d want 7", got)
	}

	// File contents are decimal text, which is what the production code
	// promises.
	b, err := os.ReadFile(tc.ctx.paths.forceFallbackCounter)
	if err != nil {
		t.Fatalf("read counter file: %v", err)
	}
	if v := strings.TrimSpace(string(b)); v != "7" {
		t.Fatalf("file %q want %q", v, "7")
	}
}

func TestForceFallbackCounter_OverwritesExisting(t *testing.T) {
	tc := newTestCtx(t)
	writeForceFallbackCounter(tc.ctx, 3)
	writeForceFallbackCounter(tc.ctx, 4)
	got, found := readForceFallbackCounter(tc.ctx)
	if !found || got != 4 {
		t.Fatalf("got (%d, %v) want (4, true)", got, found)
	}
}

func TestForceFallbackCounter_GarbageContent(t *testing.T) {
	tc := newTestCtx(t)
	if err := os.WriteFile(tc.ctx.paths.forceFallbackCounter,
		[]byte("garbage"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// fileutils.ReadSavedCounter returns (0, false) on parse error.
	got, found := readForceFallbackCounter(tc.ctx)
	if found {
		t.Fatalf("expected found=false on garbage, got (%d, true)", got)
	}
}
