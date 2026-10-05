// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stageDB builds a datastore directory and points the package at it.
func stageDB(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	db := filepath.Join(root, "db")
	if err := os.MkdirAll(filepath.Join(db, "etcd", "member"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(db, "etcd", "member", "wal"),
		[]byte("raft"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	orig := dbDir
	dbDir = func() string { return db }
	t.Cleanup(func() { dbDir = orig })
	return root
}

func snapshots(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var found []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), snapshotPrefix) {
			found = append(found, e.Name())
		}
	}
	return found
}

func TestSnapshotDBCopiesTheDatastore(t *testing.T) {
	root := stageDB(t)
	dst, err := SnapshotDB()
	if err != nil {
		t.Fatalf("SnapshotDB: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "etcd", "member", "wal"))
	if err != nil {
		t.Fatalf("read from snapshot: %v", err)
	}
	if string(got) != "raft" {
		t.Errorf("snapshot content = %q, want the datastore's", got)
	}
	if n := len(snapshots(t, root)); n != 1 {
		t.Errorf("got %d snapshots, want 1", n)
	}
}

// TestSnapshotDBKeepsOnlyOne pins the bound: without it every attempt
// leaves a full copy of the database behind, forever, on a fixed-size
// partition.
func TestSnapshotDBKeepsOnlyOne(t *testing.T) {
	root := stageDB(t)
	first, err := SnapshotDB()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// Force a distinct name; the stamp has one-second resolution.
	renamed := first + "-older"
	if err := os.Rename(first, renamed); err != nil {
		t.Fatalf("rename: %v", err)
	}
	second, err := SnapshotDB()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	got := snapshots(t, root)
	if len(got) != 1 {
		t.Fatalf("got %d snapshots (%v), want only the newest", len(got), got)
	}
	if filepath.Join(root, got[0]) != second {
		t.Errorf("kept %s, want the newest %s", got[0], second)
	}
}

func TestSnapshotDBRefusesWithoutHeadroom(t *testing.T) {
	stageDB(t)
	orig := freeSpace
	freeSpace = func(string) (uint64, error) { return 1, nil }
	t.Cleanup(func() { freeSpace = orig })

	if _, err := SnapshotDB(); err == nil {
		t.Error("snapshotted without room; filling the vault during a recovery " +
			"takes the surviving node down too")
	}
}
