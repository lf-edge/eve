// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"os"
	"path/filepath"
	"testing"
)

// stagePruneRequest redirects the request marker at a temp file.
func stagePruneRequest(t *testing.T) {
	t.Helper()
	prev := pruneRequest
	pruneRequest = filepath.Join(t.TempDir(), "kube", "witness-prune-request")
	t.Cleanup(func() { pruneRequest = prev })
}

func TestPruneRequestRoundTrip(t *testing.T) {
	stagePruneRequest(t)

	if requested, _ := PruneRequested(); requested {
		t.Fatal("a request must not be outstanding before one is raised")
	}
	if err := RequestPrune("10.244.244.5"); err != nil {
		t.Fatalf("RequestPrune: %v", err)
	}
	requested, addr := PruneRequested()
	if !requested {
		t.Fatal("request not visible after RequestPrune")
	}
	if want := "10.244.244.5"; addr != want+"\n" {
		t.Errorf("address = %q, want %q", addr, want+"\n")
	}
	// Idempotent: the witness re-raises on a retry without the node
	// seeing two distinct requests.
	if err := RequestPrune("10.244.244.5"); err != nil {
		t.Fatalf("second RequestPrune: %v", err)
	}
	if err := ClearPruneRequest(); err != nil {
		t.Fatalf("ClearPruneRequest: %v", err)
	}
	if requested, _ := PruneRequested(); requested {
		t.Error("request still outstanding after being cleared")
	}
	// Clearing an already-cleared request is how a node that restarts
	// mid-prune behaves, and must not error.
	if err := ClearPruneRequest(); err != nil {
		t.Errorf("clearing twice: %v", err)
	}
}

// TestColdJoin pins the condition that makes pruning by name safe: only
// a witness holding no etcd state may remove members named after one,
// because only then can it not be removing itself.
func TestColdJoin(t *testing.T) {
	root := t.TempDir()
	prev := dataDir
	dataDir = filepath.Join(root, "rancher", "k3s")
	t.Cleanup(func() { dataDir = prev })

	t.Run("no state at all is a cold join", func(t *testing.T) {
		if !ColdJoin() {
			t.Error("ColdJoin() = false with no data directory")
		}
	})

	t.Run("an install without a database is still cold", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(dataDir, "server", "tls"), 0755); err != nil {
			t.Fatal(err)
		}
		if !ColdJoin() {
			t.Error("ColdJoin() = false with no server/db")
		}
	})

	t.Run("an existing database is a warm restart", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(dataDir, "server", "db", "etcd"), 0755); err != nil {
			t.Fatal(err)
		}
		if ColdJoin() {
			t.Error("ColdJoin() = true with server/db present — it would prune its own member")
		}
	})
}
