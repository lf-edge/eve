// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// dbDir is the datastore directory, indirected for tests.
var dbDir = func() string { return k3s.ServerDBDir }

// snapshotPrefix names the copies a recovery leaves behind.
const snapshotPrefix = "db.recovery-"

// snapshotHeadroom is how much free space a snapshot needs relative to
// the datastore: the copy itself plus as much again. A recovery runs on
// a device that is already in trouble, and filling the vault would take
// the surviving node down too.
const snapshotHeadroom = 2

// SnapshotDB copies the datastore aside before a recovery destroys it,
// keeping exactly one such copy.
//
// Bounded on purpose. A full copy per attempt, kept forever on a
// fixed-size partition, is a slow leak nobody notices until the vault
// is full. One is enough to recover a mistake by hand.
func SnapshotDB() (string, error) {
	src := dbDir()
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("stat %s: %w", src, err)
	}
	size, err := dirSize(src)
	if err != nil {
		return "", err
	}
	free, err := freeSpace(filepath.Dir(src))
	if err != nil {
		return "", err
	}
	if free < size*snapshotHeadroom {
		return "", fmt.Errorf(
			"refusing to snapshot %s: needs %d bytes free, have %d",
			src, size*snapshotHeadroom, free)
	}

	dst := filepath.Join(filepath.Dir(src),
		snapshotPrefix+time.Now().UTC().Format("20060102T150405Z"))
	// state.CopyTree rather than cp(1): it preserves modes, ownership
	// and symlinks, skips an entry that vanishes mid-copy instead of
	// failing the whole snapshot, and creates the destination at 0700.
	// The datastore holds every Secret in the cluster, so it must not
	// land anywhere more permissive than it started.
	if err := state.CopyTree(src+"/.", dst, "quorum-snapshot"); err != nil {
		return "", fmt.Errorf("snapshot %s -> %s: %w", src, dst, err)
	}
	log.Printf("datastore snapshot at %s", dst)
	if err := pruneSnapshots(filepath.Dir(src), dst); err != nil {
		log.Printf("warning: prune old snapshots: %v", err)
	}
	return dst, nil
}

// pruneSnapshots removes every recovery snapshot except keep.
func pruneSnapshots(dir, keep string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), snapshotPrefix) {
			found = append(found, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(found)
	for _, path := range found {
		if path == keep {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		log.Printf("removed old datastore snapshot %s", path)
	}
	return nil
}

func dirSize(path string) (uint64, error) {
	var total uint64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += uint64(info.Size())
		}
		return nil
	})
	return total, err
}

// freeSpace is indirected so a test can simulate a full filesystem.
var freeSpace = freeBytes

func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}
