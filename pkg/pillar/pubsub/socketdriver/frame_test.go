// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

func payload(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestFrameRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 1000, poolMaxSize, poolMaxSize + 1, maxsize}
	var stream bytes.Buffer
	for _, size := range sizes {
		if err := WriteFrame(&stream, payload(size)); err != nil {
			t.Fatalf("WriteFrame(%d): %v", size, err)
		}
	}
	// Deliver the stream one byte at a time to exercise short reads.
	fr := NewFrameReader(iotest.OneByteReader(&stream))
	for _, size := range sizes {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame(%d): %v", size, err)
		}
		if !bytes.Equal(frame, payload(size)) {
			t.Fatalf("frame of %d bytes corrupted", size)
		}
	}
	if _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("expected io.EOF at end of stream, got %v", err)
	}
}

func TestWriteFrameRejectsOversized(t *testing.T) {
	var stream bytes.Buffer
	if err := WriteFrame(&stream, payload(maxsize+1)); err == nil {
		t.Fatal("expected an error for a frame larger than maxsize")
	}
	if stream.Len() != 0 {
		t.Fatalf("oversized frame must not be written, got %d bytes", stream.Len())
	}
}

func TestFrameReaderRejectsOversizedLength(t *testing.T) {
	var stream bytes.Buffer
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	stream.Write(hdr[:])
	fr := NewFrameReader(&stream)
	if _, err := fr.ReadFrame(); err == nil {
		t.Fatal("expected an error for a length prefix larger than maxsize")
	}
	if fr.buf != nil {
		t.Fatalf("a buffer was taken for a rejected frame")
	}
}

func TestFrameReaderTruncatedFrame(t *testing.T) {
	var stream bytes.Buffer
	if err := WriteFrame(&stream, payload(100)); err != nil {
		t.Fatal(err)
	}
	stream.Truncate(50)
	fr := NewFrameReader(&stream)
	if _, err := fr.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

// A reader must not hold a buffer while it waits for the next frame: most
// subscriptions are idle most of the time.
func TestFrameReaderHoldsNothingWhenIdle(t *testing.T) {
	var stream bytes.Buffer
	for _, size := range []int{10 * 1024, 512 * 1024, 100} {
		if err := WriteFrame(&stream, payload(size)); err != nil {
			t.Fatal(err)
		}
	}
	stats := &pubsub.SubStats{}
	fr := NewFrameReaderWithStats(&stream, stats)
	for _, size := range []int{10 * 1024, 512 * 1024, 100} {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, payload(size)) {
			t.Fatalf("frame of %d bytes corrupted", size)
		}
		if held := stats.RetainedBufBytes.Load(); held < int64(size) {
			t.Fatalf("a frame being read must be counted as held, got %d for %d bytes",
				held, size)
		}
		fr.Release()
		if fr.buf != nil || stats.RetainedBufBytes.Load() != 0 {
			t.Fatalf("buffer still held after Release: %d bytes",
				stats.RetainedBufBytes.Load())
		}
	}
	if stats.OversizedFrames.Load() != 1 {
		t.Fatalf("oversized frames %d, want 1", stats.OversizedFrames.Load())
	}
	if _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if stats.RetainedBufBytes.Load() != 0 {
		t.Fatal("a reader waiting for the next frame must hold nothing")
	}
}

// Buffers come back through a pool; a reused buffer must not leak the
// bytes of an earlier, longer frame into a shorter one.
func TestFrameReaderPooledBuffersStayIntact(t *testing.T) {
	var stream bytes.Buffer
	sizes := []int{3000, 2000, 3000, 1, 0, 4096, 1000}
	for i, size := range sizes {
		if err := WriteFrame(&stream, bytes.Repeat([]byte{byte('a' + i)}, size)); err != nil {
			t.Fatal(err)
		}
	}
	fr := NewFrameReader(&stream)
	for i, size := range sizes {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, bytes.Repeat([]byte{byte('a' + i)}, size)) {
			t.Fatalf("frame %d (%d bytes) corrupted", i, size)
		}
	}
}
