// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A limitedFileWriter must abort and delete its partial file the moment a write
// would push the on-disk byte count past the limit — this is what guarantees a
// runaway dump can never fill /persist (design doc §7).
func TestLimitedFileWriterAbortsAndDeletesPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.zst")
	w, err := newLimitedFileWriter(path, 100)
	if err != nil {
		t.Fatalf("newLimitedFileWriter: %v", err)
	}

	if n, err := w.Write(make([]byte, 60)); err != nil || n != 60 {
		t.Fatalf("first write: n=%d err=%v, want 60, nil", n, err)
	}
	if _, err := w.Write(make([]byte, 60)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second write err = %v, want ErrQuotaExceeded", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial file still present (stat err = %v), want removed", err)
	}
}

// On the success path Close finalizes and the file survives with exactly the
// bytes written.
func TestLimitedFileWriterCloseKeepsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.zst")
	w, err := newLimitedFileWriter(path, 100)
	if err != nil {
		t.Fatalf("newLimitedFileWriter: %v", err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("file content = %q, want %q", got, "hello")
	}
}

// A write landing exactly on the limit is allowed; only exceeding it aborts.
func TestLimitedFileWriterExactLimitOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.zst")
	w, err := newLimitedFileWriter(path, 50)
	if err != nil {
		t.Fatalf("newLimitedFileWriter: %v", err)
	}
	if _, err := w.Write(make([]byte, 50)); err != nil {
		t.Fatalf("write at exact limit: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != 50 {
		t.Fatalf("stat: size=%v err=%v, want 50", fi, err)
	}
}
