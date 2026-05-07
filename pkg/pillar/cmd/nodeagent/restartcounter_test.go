// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncrementRestartCounterIn_FileAbsent(t *testing.T) {
	initTestLog()
	path := filepath.Join(t.TempDir(), "restartcounter")

	got := incrementRestartCounterIn(path)
	if got != 0 {
		t.Fatalf("expected 0 on absent file, got %d", got)
	}
	got = readCounter(t, path)
	if got != 1 {
		t.Fatalf("expected file=1 after first call, got %d", got)
	}
}

func TestIncrementRestartCounterIn_ExistingValue(t *testing.T) {
	initTestLog()
	path := filepath.Join(t.TempDir(), "restartcounter")
	if err := os.WriteFile(path, []byte("42"), 0644); err != nil {
		t.Fatal(err)
	}

	got := incrementRestartCounterIn(path)
	if got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	got = readCounter(t, path)
	if got != 43 {
		t.Fatalf("expected file=43, got %d", got)
	}
}

func TestIncrementRestartCounterIn_GarbageContent(t *testing.T) {
	initTestLog()
	path := filepath.Join(t.TempDir(), "restartcounter")
	if err := os.WriteFile(path, []byte("not-a-number"), 0644); err != nil {
		t.Fatal(err)
	}

	got := incrementRestartCounterIn(path)
	if got != 0 {
		t.Fatalf("expected 0 on garbage, got %d", got)
	}
	got = readCounter(t, path)
	if got != 1 {
		t.Fatalf("expected file=1 after garbage overwrite, got %d", got)
	}
}

// TestIncrementRestartCounter_Wrapper verifies the production wrapper
// reads ctx.paths.restartCounterFile.
func TestIncrementRestartCounter_Wrapper(t *testing.T) {
	tc := newTestCtx()
	tc.ctx.paths.restartCounterFile = filepath.Join(t.TempDir(), "rc")
	if err := os.WriteFile(tc.ctx.paths.restartCounterFile,
		[]byte("99"), 0644); err != nil {
		t.Fatal(err)
	}

	got := incrementRestartCounter(tc.ctx)
	if got != 99 {
		t.Errorf("expected 99, got %d", got)
	}
	if got = readCounter(t, tc.ctx.paths.restartCounterFile); got != 100 {
		t.Errorf("expected file=100, got %d", got)
	}
}

// readCounter reads the file and parses it as a decimal uint32. The test
// asserts equality on the in-memory value rather than going through
// strconv to avoid duplicating the production parse logic.
func readCounter(t *testing.T, path string) uint32 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	s := strings.TrimSpace(string(b))
	var v uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit in counter file: %q", s)
		}
		v = v*10 + uint32(c-'0')
	}
	return v
}
