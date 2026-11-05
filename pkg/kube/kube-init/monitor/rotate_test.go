// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

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
