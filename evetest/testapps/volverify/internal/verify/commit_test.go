// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"testing"
)

func TestCommitPingPong(t *testing.T) {
	dir := t.TempDir()
	if got := readCommit(dir); got != -1 {
		t.Fatalf("fresh volume: got committed=%d, want -1", got)
	}
	for i := 0; i < 5; i++ {
		gen := nextGeneration(dir)
		if err := writeCommit(dir, commitRecord{generation: gen, index: int64(i * 10)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := readCommit(dir); got != 40 {
		t.Fatalf("got committed=%d, want 40", got)
	}
}

func TestCommitTornNewestSlotFallsBack(t *testing.T) {
	dir := t.TempDir()
	// generation 0 -> slot 0 (index 100), generation 1 -> slot 1 (index 200).
	if err := writeCommit(dir, commitRecord{generation: 0, index: 100}); err != nil {
		t.Fatal(err)
	}
	if err := writeCommit(dir, commitRecord{generation: 1, index: 200}); err != nil {
		t.Fatal(err)
	}
	if got := readCommit(dir); got != 200 {
		t.Fatalf("got %d, want 200", got)
	}
	// Tear the newest slot (slot 1); recovery must fall back to slot 0.
	if err := os.WriteFile(slotPath(dir, 1), []byte("torn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCommit(dir); got != 100 {
		t.Fatalf("after tearing newest slot: got %d, want 100", got)
	}
}
