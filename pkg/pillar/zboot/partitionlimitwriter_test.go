// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package zboot

import (
	"bytes"
	"errors"
	"testing"
)

// failWriter always fails, to exercise the deferred-error path.
type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) {
	return 0, errors.New("device write error")
}

// TestPartitionLimitWriterUnderLimit: writes that stay within the bound pass
// through unchanged and report full success.
func TestPartitionLimitWriterUnderLimit(t *testing.T) {
	var buf bytes.Buffer
	w := &partitionLimitWriter{w: &buf, max: 10}

	if n, err := w.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("first write = (%d, %v), want (5, nil)", n, err)
	}
	// 5+5 == max (10), which is not greater than max, so still allowed.
	if n, err := w.Write([]byte("world")); err != nil || n != 5 {
		t.Fatalf("second write = (%d, %v), want (5, nil)", n, err)
	}
	if w.exceeded {
		t.Fatalf("exceeded set when exactly at the limit")
	}
	if got := buf.String(); got != "helloworld" {
		t.Fatalf("buffer = %q, want %q", got, "helloworld")
	}
	if w.werr != nil {
		t.Fatalf("unexpected werr: %v", w.werr)
	}
}

// TestPartitionLimitWriterExceeds: a write crossing the bound must NOT return an
// error (returning one would deadlock the oras pull pipeline). It reports full
// success, writes only the part that fits, and flags the overflow.
func TestPartitionLimitWriterExceeds(t *testing.T) {
	var buf bytes.Buffer
	w := &partitionLimitWriter{w: &buf, max: 10}

	if n, err := w.Write([]byte("12345678")); err != nil || n != 8 {
		t.Fatalf("first write = (%d, %v), want (8, nil)", n, err)
	}
	// 8+5 = 13 > 10: overflow.
	n, err := w.Write([]byte("ABCDE"))
	if err != nil {
		t.Fatalf("overflow write returned error %v; must never error mid-stream", err)
	}
	if n != 5 {
		t.Fatalf("overflow write n = %d, want 5 (full length claimed)", n)
	}
	if !w.exceeded {
		t.Fatalf("exceeded not set after crossing the limit")
	}
	// Only the 2 bytes that still fit (10-8) should reach the device.
	if got := buf.String(); got != "12345678AB" {
		t.Fatalf("buffer = %q, want %q", got, "12345678AB")
	}
	if w.written != 13 {
		t.Fatalf("written = %d, want 13 (counts all bytes seen)", w.written)
	}
}

// TestPartitionLimitWriterMaxZero: a zero max disables the bound entirely.
func TestPartitionLimitWriterMaxZero(t *testing.T) {
	var buf bytes.Buffer
	w := &partitionLimitWriter{w: &buf, max: 0}

	big := bytes.Repeat([]byte("x"), 1000)
	if n, err := w.Write(big); err != nil || n != 1000 {
		t.Fatalf("write = (%d, %v), want (1000, nil)", n, err)
	}
	if w.exceeded {
		t.Fatalf("exceeded set with max==0")
	}
	if buf.Len() != 1000 {
		t.Fatalf("buffer len = %d, want 1000", buf.Len())
	}
}

// TestPartitionLimitWriterDeferredDeviceError: an underlying device error is
// recorded for the caller to surface after the pull, never returned mid-stream.
func TestPartitionLimitWriterDeferredDeviceError(t *testing.T) {
	w := &partitionLimitWriter{w: failWriter{}, max: 100}

	n, err := w.Write([]byte("data"))
	if err != nil {
		t.Fatalf("Write returned error %v; must defer device errors", err)
	}
	if n != 4 {
		t.Fatalf("Write n = %d, want 4", n)
	}
	if w.werr == nil {
		t.Fatalf("device error not recorded in werr")
	}
}
