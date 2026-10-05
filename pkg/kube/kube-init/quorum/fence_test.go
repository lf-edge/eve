// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"path/filepath"
	"strings"
	"testing"
)

func stageFence(t *testing.T) {
	t.Helper()
	orig := witnessFence
	witnessFence = filepath.Join(t.TempDir(), "kube", "witness-fence")
	t.Cleanup(func() { witnessFence = orig })
}

func TestWitnessFence(t *testing.T) {
	stageFence(t)

	if held, _ := WitnessFenceHeld(); held {
		t.Fatal("fence reported held before anything took it")
	}
	if err := HoldWitnessFence("cluster reset in progress"); err != nil {
		t.Fatalf("HoldWitnessFence: %v", err)
	}
	held, reason := WitnessFenceHeld()
	if !held {
		t.Fatal("fence not held after taking it")
	}
	if !strings.Contains(reason, "cluster reset") {
		t.Errorf("reason = %q, want it to say why", reason)
	}
	if err := ReleaseWitnessFence(); err != nil {
		t.Fatalf("ReleaseWitnessFence: %v", err)
	}
	if held, _ := WitnessFenceHeld(); held {
		t.Error("fence still held after release")
	}
}

// TestHoldWitnessFenceIsRepeatable: a promote that retries must be able
// to take a fence it already holds.
func TestHoldWitnessFenceIsRepeatable(t *testing.T) {
	stageFence(t)
	if err := HoldWitnessFence("first"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := HoldWitnessFence("second"); err != nil {
		t.Fatalf("second: %v", err)
	}
	if _, reason := WitnessFenceHeld(); !strings.Contains(reason, "second") {
		t.Errorf("reason = %q, want the latest", reason)
	}
}

func TestReleaseWitnessFenceIsIdempotent(t *testing.T) {
	stageFence(t)
	if err := ReleaseWitnessFence(); err != nil {
		t.Errorf("releasing an unheld fence: %v", err)
	}
}
