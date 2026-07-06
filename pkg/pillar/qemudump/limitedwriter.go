// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"errors"
	"fmt"
	"os"
)

// ErrQuotaExceeded is returned by a dump writer when a write would push the
// on-disk dump past its allowed size. The partial file is removed before the
// error is returned.
var ErrQuotaExceeded = errors.New("qemudump: dump exceeded its storage limit")

// limitedFileWriter writes to a file while enforcing a hard byte ceiling on the
// bytes actually written to disk. The moment a write would cross the limit it
// aborts: the file is closed and removed, and every subsequent call returns
// ErrQuotaExceeded. This is the on-the-fly quota primitive —
// the compressed dump stream is written through it so a runaway dump can never
// fill /persist.
type limitedFileWriter struct {
	path    string
	f       *os.File
	limit   uint64
	written uint64
	aborted bool
}

func newLimitedFileWriter(path string, limit uint64) (*limitedFileWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("qemudump: create %s: %w", path, err)
	}
	return &limitedFileWriter{path: path, f: f, limit: limit}, nil
}

func (w *limitedFileWriter) Write(p []byte) (int, error) {
	if w.aborted {
		return 0, ErrQuotaExceeded
	}
	if w.written+uint64(len(p)) > w.limit {
		w.abort()
		return 0, ErrQuotaExceeded
	}
	n, err := w.f.Write(p)
	w.written += uint64(n)
	return n, err
}

// abort closes and removes the partial file and latches the aborted state.
func (w *limitedFileWriter) abort() {
	w.aborted = true
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	os.Remove(w.path)
}

// Close finalizes the file on the success path. After an abort it is a no-op
// (the file is already gone).
func (w *limitedFileWriter) Close() error {
	if w.aborted || w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
