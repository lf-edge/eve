// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// TestCompressedFrameRoundTrip checks that a message above maxsize is
// compressed into a frame, flagged, and read back whole into a buffer the
// caller owns.
func TestCompressedFrameRoundTrip(t *testing.T) {
	msg := bytes.Repeat([]byte(`{"Port":"eth0","Pacfile":"x"} `), 200000)
	frame, err := compress(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) > maxsize {
		t.Fatalf("frame of %d bytes", len(frame))
	}
	var stream bytes.Buffer
	if err := writeFrame(&stream, frame, true); err != nil {
		t.Fatal(err)
	}
	stats := &pubsub.SubStats{}
	fr := NewFrameReaderWithStats(&stream, stats)
	got, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %d bytes, sent %d", len(got), len(msg))
	}
	if !fr.Owned() {
		t.Error("a decompressed message is not in a buffer of its own")
	}
	if stats.CompressedFrames.Load() != 1 || stats.DecompressedBytes.Load() != int64(len(msg)) {
		t.Errorf("compressed frames %d, decompressed bytes %d",
			stats.CompressedFrames.Load(), stats.DecompressedBytes.Load())
	}
	fr.Release()
	if n := stats.RetainedBufBytes.Load(); n != 0 {
		t.Errorf("%d bytes held after Release", n)
	}
}

// TestCompressRefuses checks the two limits of a message above maxsize: it
// must compress into maxsize bytes, and be at most maxMessageSize.
func TestCompressRefuses(t *testing.T) {
	random := make([]byte, 2*maxsize)
	_, _ = rand.Read(random)
	if _, err := compress(random); err == nil {
		t.Error("incompressible message of 2MB accepted")
	}
	if _, err := compress(make([]byte, maxMessageSize+1)); err == nil {
		t.Error("message above maxMessageSize accepted")
	}
}

// TestDecompressRefusesOversizedMessage checks that a small frame which
// decompresses beyond maxMessageSize is an error rather than an allocation
// of that size.
func TestDecompressRefusesOversizedMessage(t *testing.T) {
	var frame bytes.Buffer
	enc, err := zstd.NewWriter(&frame)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 1<<20)
	for i := 0; i < maxMessageSize>>20+16; i++ {
		_, _ = enc.Write(zeros)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	if err := writeFrame(&stream, frame.Bytes(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFrameReader(&stream).ReadFrame(); err == nil {
		t.Fatalf("a %d byte frame of %d MB of zeros was accepted",
			frame.Len(), maxMessageSize>>20+16)
	}
}
