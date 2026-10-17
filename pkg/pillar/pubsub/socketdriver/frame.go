// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// Messages are sent over unix stream sockets as frames: a 4-byte
// little-endian payload length followed by the payload. A message larger
// than maxsize is sent compressed with zstd, and compressedFlag set in the
// length marks such a frame.
const (
	// maxsize is the largest frame payload we send or accept, and the
	// largest message sent as it is.
	maxsize = 1024 * 1024
	// maxMessageSize is the largest message: one above maxsize must
	// compress into a frame of at most maxsize.
	maxMessageSize = 128 * 1024 * 1024
	// compressedFlag in the length of a frame marks a compressed payload.
	compressedFlag = 1 << 31
	// maxWindow is the largest zstd window used. Messages repeat the same
	// content, e.g. certificates in every port of every DevicePortConfig of
	// a DevicePortConfigList, so the window should span a whole such
	// repetition.
	maxWindow = 32 * 1024 * 1024
	// poolMaxSize is the largest frame read into a pooled buffer. Larger
	// frames get a buffer of their own, garbage once the frame is consumed.
	poolMaxSize = 64 * 1024
)

// Read buffers are shared through one pool per size class and held by a
// FrameReader only while it reads a frame and its caller consumes it, not
// while it waits for the next frame: most subscriptions are idle most of
// the time.
var (
	bufClasses = [...]int{1 << 10, 4 << 10, 16 << 10, poolMaxSize}
	bufPools   [len(bufClasses)]sync.Pool
)

// WriteFrame writes payload as a single frame.
func WriteFrame(w io.Writer, payload []byte) error {
	return writeFrame(w, payload, false, nil)
}

// writeFrame writes payload as a single frame, flagged as compressed if
// it is, counting its allocations in a: the header and the two-element
// net.Buffers, which escape to the heap.
func writeFrame(w io.Writer, payload []byte, compressed bool, a *pubsub.Alloc) error {
	if len(payload) > maxsize {
		return fmt.Errorf("frame of %d bytes exceeds max %d",
			len(payload), maxsize)
	}
	if a != nil {
		a.Add(4)
		a.Add(24)
		a.Add(48)
	}
	n := uint32(len(payload))
	if compressed {
		n |= compressedFlag
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], n)
	bufs := net.Buffers{hdr[:], payload}
	_, err := bufs.WriteTo(w)
	return err
}

// FrameReader reads frames from a stream.
type FrameReader struct {
	r     io.Reader
	hdr   [4]byte
	buf   *[]byte // the buffer of the current frame, if any
	class int     // pool of buf, or -1 for a buffer of its own
	stats *pubsub.SubStats
	alloc *pubsub.Alloc // counts buffers when there are no stats
}

func (fr *FrameReader) countAlloc(n int) {
	if fr.stats != nil {
		fr.stats.AllocReadBuf.Add(n)
	} else if fr.alloc != nil {
		fr.alloc.Add(n)
	}
}

// NewFrameReader returns a FrameReader reading from r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r}
}

// NewFrameReaderWithStats returns a FrameReader which counts the frames it
// reads and the buffer it holds in stats.
func NewFrameReaderWithStats(r io.Reader, stats *pubsub.SubStats) *FrameReader {
	return &FrameReader{r: r, stats: stats}
}

// Owned reports whether the current frame is in a buffer of its own, not
// one from a pool: its caller may keep parts of it after Release.
func (fr *FrameReader) Owned() bool {
	return fr.buf != nil && fr.class < 0
}

// Release gives back the buffer of the current frame, which must no longer
// be used unless Owned. ReadFrame does it before waiting for the next
// frame.
func (fr *FrameReader) Release() {
	if fr.buf == nil {
		return
	}
	if fr.stats != nil {
		fr.stats.RetainedBufBytes.Add(-int64(cap(*fr.buf)))
	}
	if fr.class >= 0 {
		bufPools[fr.class].Put(fr.buf)
	}
	fr.buf = nil
}

func (fr *FrameReader) acquire(size int) []byte {
	fr.class = -1
	for i, c := range bufClasses {
		if size <= c {
			fr.class = i
			break
		}
	}
	if fr.class >= 0 {
		if b, ok := bufPools[fr.class].Get().(*[]byte); ok {
			fr.buf = b
		} else {
			b := make([]byte, bufClasses[fr.class])
			fr.buf = &b
			fr.countAlloc(len(b))
			fr.countAlloc(8) // the *[]byte kept in the pool
		}
	} else {
		b := make([]byte, size)
		fr.buf = &b
		if fr.stats != nil {
			fr.stats.OversizedFrames.Add(1)
		}
		fr.countAlloc(size)
	}
	if fr.stats != nil {
		fr.stats.RetainedBufBytes.Add(int64(cap(*fr.buf)))
		fr.stats.BufTakenBytes.Add(int64(cap(*fr.buf)))
	}
	return (*fr.buf)[:size]
}

// ReadFrame returns the payload of the next frame, decompressed if it was
// compressed, valid until Release or the next ReadFrame. After an error the
// stream is no longer in sync and must be closed.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	fr.Release()
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(fr.hdr[:])
	compressed := n&compressedFlag != 0
	n &^= compressedFlag
	if n > maxsize {
		return nil, fmt.Errorf("frame of %d bytes exceeds max %d", n, maxsize)
	}
	buf := fr.acquire(int(n))
	if _, err := io.ReadFull(fr.r, buf); err != nil {
		fr.Release()
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if fr.stats != nil {
		fr.stats.AddFrame(len(buf))
	}
	if compressed {
		return fr.decompress(buf)
	}
	return buf, nil
}

// decompress replaces the compressed frame in buf by its message, in a
// buffer of its own.
func (fr *FrameReader) decompress(buf []byte) ([]byte, error) {
	msg, err := decompress(buf)
	fr.Release()
	if err != nil {
		return nil, fmt.Errorf("frame of %d bytes: %w", len(buf), err)
	}
	fr.buf, fr.class = &msg, -1
	fr.countAlloc(cap(msg))
	if fr.stats != nil {
		fr.stats.RetainedBufBytes.Add(int64(cap(msg)))
		fr.stats.CompressedFrames.Add(1)
		fr.stats.DecompressedBytes.Add(int64(len(msg)))
	}
	return msg, nil
}

// compress returns msg compressed with zstd, or an error if msg is larger
// than maxMessageSize or does not compress into maxsize bytes. Messages this
// large are rare, so an encoder is made for each and its window, which is
// most of its memory, is sized to the message.
func compress(msg []byte) ([]byte, error) {
	if len(msg) > maxMessageSize {
		return nil, fmt.Errorf("message of %d bytes exceeds max %d",
			len(msg), maxMessageSize)
	}
	window := zstd.MinWindowSize
	for window < len(msg) && window < maxWindow {
		window *= 2
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest),
		zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(window))
	if err != nil {
		return nil, err
	}
	defer enc.Close()
	out := enc.EncodeAll(msg, nil)
	if len(out) > maxsize {
		return nil, fmt.Errorf("message of %d bytes compresses to %d bytes, max %d",
			len(msg), len(out), maxsize)
	}
	return out, nil
}

// decompress returns the message in a compressed frame. The decoder refuses
// a message above maxMessageSize before allocating it.
func decompress(frame []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxMessageSize),
		zstd.WithDecoderMaxWindow(maxWindow))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(frame, nil)
}
