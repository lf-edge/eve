// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package socketdriver

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// Messages are sent over unix stream sockets as frames: a 4-byte
// little-endian payload length followed by the payload.
const (
	// maxsize is the largest frame payload we send or accept.
	maxsize = 1024 * 1024
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
	if len(payload) > maxsize {
		return fmt.Errorf("frame of %d bytes exceeds max %d",
			len(payload), maxsize)
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
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

// Release gives back the buffer of the current frame, which must no longer
// be used. ReadFrame does it before waiting for the next frame.
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
		}
	} else {
		b := make([]byte, size)
		fr.buf = &b
		if fr.stats != nil {
			fr.stats.OversizedFrames.Add(1)
		}
	}
	if fr.stats != nil {
		fr.stats.RetainedBufBytes.Add(int64(cap(*fr.buf)))
	}
	return (*fr.buf)[:size]
}

// ReadFrame returns the payload of the next frame, valid until Release or
// the next ReadFrame. After an error the stream is no longer in sync and
// must be closed.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	fr.Release()
	if _, err := io.ReadFull(fr.r, fr.hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(fr.hdr[:])
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
	return buf, nil
}
