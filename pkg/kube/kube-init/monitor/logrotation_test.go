// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/role"
)

// The witness shares the log directory with the node's kube role, so
// each role may only rotate and prune what it writes itself.
func TestLogOwnershipPerRole(t *testing.T) {
	restore := role.Override(role.Witness)
	if got := rotatedLogs(); !slices.Equal(got, []string{"witness.log"}) {
		t.Errorf("witness rotates %v, want only witness.log", got)
	}
	if got := archivePrefix(); got != "witness-" {
		t.Errorf("witness archive prefix = %q, want witness-", got)
	}
	restore()

	restore = role.Override(role.Kube)
	defer restore()
	got := rotatedLogs()
	if slices.Contains(got, "witness.log") || !slices.Contains(got, "multus.log") {
		t.Errorf("node rotates %v, want multus.log and not witness.log", got)
	}
	// k3s rotates k3s.log itself; a copy-truncate of a file its
	// lumberjack holds open leaves a NUL-filled hole.
	if slices.Contains(got, "k3s.log") {
		t.Errorf("node rotates %v, must leave k3s.log to k3s", got)
	}
	if got := archivePrefix(); got != "k3s-" {
		t.Errorf("node archive prefix = %q, want k3s-", got)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

func TestRotateLogFileBelowThresholdIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	if err := os.WriteFile(path, []byte("small\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rotateLogFile(path)
	if got := fileSize(t, path); got != 6 {
		t.Errorf("live file size = %d, want untouched 6", got)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("unexpected backup created: %v", err)
	}
}

func TestRotateLogFileCopyTruncatesAndShifts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.log")
	fill := func(marker byte) {
		t.Helper()
		if err := os.WriteFile(path, bytes.Repeat([]byte{marker}, maxLogSize+1), 0644); err != nil {
			t.Fatal(err)
		}
	}

	for i, marker := range []byte{'a', 'b', 'c', 'd'} {
		fill(marker)
		rotateLogFile(path)
		if got := fileSize(t, path); got != 0 {
			t.Fatalf("round %d: live file size = %d, want 0", i, got)
		}
	}

	// Newest backup is .1, oldest surviving is .3; 'a' fell off.
	for suffix, want := range map[string]byte{".1": 'd', ".2": 'c', ".3": 'b'} {
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatalf("read %s: %v", suffix, err)
		}
		if len(data) != maxLogSize+1 || data[0] != want {
			t.Errorf("%s: len=%d first=%q, want len=%d first=%q",
				suffix, len(data), data[0], maxLogSize+1, want)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Errorf("backup .4 must not exist: %v", err)
	}
}
