// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package witness

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
)

// TestWanted pins the placement rule: the witness co-locates with
// whichever device owns join_server_ip, so seed ownership decides,
// and no witness IP means no witness anywhere.
func TestWanted(t *testing.T) {
	cases := []struct {
		name string
		cs   *k3s.ClusterStatus
		want bool
	}{
		{"no status", nil, false},
		{"seed with witness IP", &k3s.ClusterStatus{
			WitnessIP: "10.244.244.5", IsBootstrapNode: true}, true},
		{"seed without witness IP", &k3s.ClusterStatus{
			IsBootstrapNode: true}, false},
		{"non-seed with witness IP", &k3s.ClusterStatus{
			WitnessIP: "10.244.244.5"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Wanted(c.cs); got != c.want {
				t.Errorf("Wanted() = %v, want %v", got, c.want)
			}
		})
	}
}

// stageState builds a data dir with the files a joined witness has, plus
// the install that must survive a wipe, and points the package at it.
func stageState(t *testing.T) (dir string) {
	t.Helper()
	root := t.TempDir()
	origData, origMarker := dataDir, membershipMarker
	dataDir = filepath.Join(root, "rancher", "k3s")
	membershipMarker = filepath.Join(root, "witness", "membership")
	t.Cleanup(func() { dataDir, membershipMarker = origData, origMarker })

	for _, sub := range []string{"server/db", "server/tls", "server/cred", "agent", "data"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, sub, "f"), []byte("x"), 0644); err != nil {
			t.Fatalf("write %s: %v", sub, err)
		}
	}
	return root
}

func status(clusterID string, gen uint32) *k3s.ClusterStatus {
	return &k3s.ClusterStatus{ClusterID: clusterID, QuorumRecoveryGeneration: gen}
}

func dbExists() bool {
	_, err := os.Stat(filepath.Join(dataDir, "server", "db", "f"))
	return err == nil
}

func TestSyncMembership(t *testing.T) {
	t.Run("first run records without wiping", func(t *testing.T) {
		stageState(t)
		if err := SyncMembership(status("cluster-a", 0)); err != nil {
			t.Fatalf("SyncMembership: %v", err)
		}
		if !dbExists() {
			t.Error("first run must not wipe: there is no prior membership to differ from")
		}
	})

	t.Run("unchanged membership keeps state", func(t *testing.T) {
		stageState(t)
		if err := SyncMembership(status("cluster-a", 1)); err != nil {
			t.Fatalf("first: %v", err)
		}
		if err := SyncMembership(status("cluster-a", 1)); err != nil {
			t.Fatalf("second: %v", err)
		}
		if !dbExists() {
			t.Error("wiped state despite unchanged membership")
		}
	})

	t.Run("different cluster wipes", func(t *testing.T) {
		stageState(t)
		if err := SyncMembership(status("cluster-a", 0)); err != nil {
			t.Fatalf("first: %v", err)
		}
		if err := SyncMembership(status("cluster-b", 0)); err != nil {
			t.Fatalf("second: %v", err)
		}
		if dbExists() {
			t.Error("state from another cluster must be wiped")
		}
	})

	// A quorum recovery keeps the cluster UUID but resets etcd, so state
	// from before it is unusable and a UUID-only marker would see no
	// change.
	t.Run("recovery generation bump wipes", func(t *testing.T) {
		stageState(t)
		if err := SyncMembership(status("cluster-a", 0)); err != nil {
			t.Fatalf("first: %v", err)
		}
		if err := SyncMembership(status("cluster-a", 1)); err != nil {
			t.Fatalf("second: %v", err)
		}
		if dbExists() {
			t.Error("state from before a quorum recovery must be wiped")
		}
	})

	t.Run("wipe keeps the k3s install", func(t *testing.T) {
		stageState(t)
		if err := SyncMembership(status("cluster-a", 0)); err != nil {
			t.Fatalf("first: %v", err)
		}
		if err := SyncMembership(status("cluster-b", 0)); err != nil {
			t.Fatalf("second: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "data", "f")); err != nil {
			t.Errorf("wipe removed the cluster-independent k3s install: %v", err)
		}
	})
}
