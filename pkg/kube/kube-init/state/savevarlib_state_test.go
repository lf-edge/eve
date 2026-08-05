// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mkVarLib builds a miniature /var/lib holding one entry of each class:
// real state, re-derivable bulk, a marker, and a cluster-only artifact.
func mkVarLib(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	// state
	write("rancher/k3s/server/tls/server-ca.crt", "CA")
	write("rancher/k3s/server/token", "tok")
	write("rancher/k3s/server/cred/passwd", "pw")
	write("rancher/k3s/agent/client-kubelet.crt", "kubelet")
	// node-token/agent-token are symlinks to token on a real node.
	if err := os.Symlink(filepath.Join(root, "rancher/k3s/server/token"),
		filepath.Join(root, "rancher/k3s/server/node-token")); err != nil {
		t.Fatalf("symlink node-token: %v", err)
	}
	write("all_components_initialized", "")
	write("node-labels-initialized", "")
	// re-derivable bulk — must NOT be snapshotted
	write("rancher/k3s/server/data/bulk.bin", "231MB pretend")
	write("cni/bin/bridge", "cni binary")
	write("k3s/agent.bin", "k3s binary")
	return root
}

func TestSaveVarLibStateSnapshotsOnlyState(t *testing.T) {
	src := mkVarLib(t)
	dst := filepath.Join(t.TempDir(), "backup")

	// No datastore in this fixture; the copy must still succeed.
	if err := saveVarLibTo(src, dst); err != nil {
		t.Fatalf("saveVarLibTo: %v", err)
	}

	for _, want := range []string{
		"rancher/k3s/server/tls/server-ca.crt",
		"rancher/k3s/server/token",
		"rancher/k3s/server/cred/passwd",
		"rancher/k3s/agent/client-kubelet.crt",
		"rancher/k3s/server/node-token",
		"all_components_initialized",
		"node-labels-initialized",
	} {
		if _, err := os.Stat(filepath.Join(dst, want)); err != nil {
			t.Errorf("state %s missing from snapshot: %v", want, err)
		}
	}
	// The whole point: ~419MB of re-derivable content stays behind.
	for _, unwanted := range []string{
		"rancher/k3s/server/data/bulk.bin",
		"cni/bin/bridge",
		"k3s/agent.bin",
	} {
		if _, err := os.Stat(filepath.Join(dst, unwanted)); err == nil {
			t.Errorf("re-derivable %s must not be snapshotted", unwanted)
		}
	}
}

// TestRestoreVarLibPurgesClusterArtifacts is the guard for the overlay
// restore: a cluster-mode etcd datastore left next to the restored kine
// one would give k3s two conflicting datastores, and would make
// etcdClusterInitialized() report a cluster that no longer exists.
func TestRestoreVarLibPurgesClusterArtifacts(t *testing.T) {
	backup := mkVarLib(t)
	live := t.TempDir()

	// Live tree is mid-rollback: cluster-mode etcd member data present.
	member := filepath.Join(live, "rancher/k3s/server/db/etcd/member")
	if err := os.MkdirAll(member, 0700); err != nil {
		t.Fatalf("mkdir member: %v", err)
	}
	if err := os.WriteFile(filepath.Join(member, "wal"), []byte("x"), 0600); err != nil {
		t.Fatalf("write wal: %v", err)
	}
	// Binaries the state-only snapshot does not carry must survive.
	bin := filepath.Join(live, "k3s/agent.bin")
	if err := os.MkdirAll(filepath.Dir(bin), 0700); err != nil {
		t.Fatalf("mkdir k3s: %v", err)
	}
	if err := os.WriteFile(bin, []byte("k3s binary"), 0600); err != nil {
		t.Fatalf("write bin: %v", err)
	}

	if err := restoreVarLibFrom(backup, live); err != nil {
		t.Fatalf("restoreVarLibFrom: %v", err)
	}

	if _, err := os.Stat(filepath.Join(live, "rancher/k3s/server/db/etcd")); err == nil {
		t.Error("cluster-mode etcd datastore survived the rollback")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Errorf("re-derivable binary must survive an overlay restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(live, "rancher/k3s/server/token")); err != nil {
		t.Errorf("state not restored: %v", err)
	}
}

// TestSqliteVacuumIntoLiveWriter is the claim the whole change rests on:
// an online-consistent copy of the datastore while a writer is active.
// Skipped where sqlite3 is unavailable; the device image ships it.
func TestSqliteVacuumIntoLiveWriter(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 not installed")
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")

	run := func(sql string) {
		t.Helper()
		if out, err := exec.Command("sqlite3", db, sql).CombinedOutput(); err != nil {
			t.Fatalf("sqlite3 %q: %v (%s)", sql, err, out)
		}
	}
	// kine runs in WAL mode, where a naive file copy is not consistent.
	run("PRAGMA journal_mode=WAL;")
	run("CREATE TABLE kv (k INTEGER PRIMARY KEY, v TEXT);")
	run("INSERT INTO kv (v) VALUES ('a'),('b'),('c');")

	// Hold a writer open across the snapshot.
	writer := exec.Command("sqlite3", db,
		"BEGIN; INSERT INTO kv (v) VALUES ('live'); COMMIT;")
	if out, err := writer.CombinedOutput(); err != nil {
		t.Fatalf("live write: %v (%s)", err, out)
	}

	out := filepath.Join(dir, "snap.db")
	if err := sqliteVacuumInto(db, out); err != nil {
		t.Fatalf("sqliteVacuumInto: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("snapshot not written: %v", err)
	}
	got, err := exec.Command("sqlite3", out, "SELECT count(*) FROM kv;").Output()
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if s := string(got); s != "4\n" {
		t.Errorf("snapshot row count = %q, want \"4\\n\" (copy not consistent)", s)
	}
	// Re-running must not fail on an existing destination.
	if err := sqliteVacuumInto(db, out); err != nil {
		t.Errorf("second VACUUM INTO over existing dst: %v", err)
	}
}
