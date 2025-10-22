/*
Package framed provides an implementations of io.Writer and io.Reader that write
and read whole frames only.

Frames are length-prefixed.  The first two bytes are an unsigned 16 bit int
stored in little-endian byte order indicating the length of the content.  The
remaining bytes are the actual content of the frame.

The use of a uint16 means that the maximum possible frame size (MaxFrameSize)
is 65535.

The frame size can be increased to 4294967295 bytes by calling EnableBigFrames()
on the corresponding Reader and Writer.
*/
package framed

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/oxtoacart/bpool"
)

var endianness = binary.LittleEndian

const (
	// FrameHeaderBits is the size of the frame header in bits
	FrameHeaderBits = 16

	// FrameHeaderBitsBig is the size of the frame header in bits when big frames are enabled
	FrameHeaderBitsBig = 32

	// FrameHeaderLength is the size of the frame header in bytes
	FrameHeaderLength = FrameHeaderBits / 8

	// FrameHeaderLengthBig is the size of the frame header in bytes when big frames are enabled
	FrameHeaderLengthBig = FrameHeaderBitsBig / 8

	// MaxFrameLength is the maximum possible size of a frame (not including the
	// length prefix)
	MaxFrameLength = 1<<FrameHeaderBits - 1

	// MaxFrameLengthBigFrames is the maximum possible size of a frame (not
	// including the length prefix) when big frames are enabled.
	MaxFrameLengthBigFrames = 1<<FrameHeaderBitsBig - 1

	tooLongError = "Attempted to write frame of length %d which is longer than maximum allowed length of %d"
)

// Framed is the common interface for framed Readers and Writers
type Framed interface {
	// EnableBigFrames enables support for frames up to 4294967295 bytes in length
	// by using BigEndian byte order for the frame size and supporting expansion of
	// the size header from 2 to 4 bytes.
	EnableBigFrames(framed interface{})

	// DisableThreadSafety disables thread safety on reading and writing.
	DisableThreadSafety()
}

type framed struct {
	bigFramesEnabled     bool
	headerLength         int
	maxFrameLength       int64
	threadSafetyDisabled bool
	mutex                sync.Mutex
}

func newFramed() framed {
	return framed{
		headerLength:   FrameHeaderLength,
		maxFrameLength: MaxFrameLength,
	}
}

func (fr *framed) EnableBigFrames() {
	fr.mutex.Lock()
	fr.bigFramesEnabled = true
	fr.headerLength = FrameHeaderLengthBig
	fr.maxFrameLength = MaxFrameLengthBigFrames
	fr.mutex.Unlock()
}

func (fr *framed) DisableThreadSafety() {
	fr.threadSafetyDisabled = true
}

/*
A Reader enhances an io.ReadCloser to read data in contiguous frames. It
implements the io.Reader interface, but unlike typical io.Readers it only
returns whole frames.

A Reader also supports the ability to read frames using dynamically allocated
buffers via the ReadFrame method.
*/
type Reader struct {
	Stream io.Reader // the raw underlying connection
	framed
	lb []byte
}

/*
A Writer enhances an io.WriteCloser to write data in contiguous frames. It
implements the io.Writer interface, but unlike typical io.Writers, it includes
information that allows a corresponding Reader to read whole frames without them
being fragmented.

A Writer also supports a method that writes multiple buffers to the underlying
stream as a single frame.
*/
type Writer struct {
	Stream io.Writer // the raw underlying connection
	framed
}

/*
ReadWriteCloser combines a Reader and a Writer on top of an underlying
ReadWriteCloser.
*/
type ReadWriteCloser struct {
	Reader
	Writer
	io.Closer
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		Stream: r,
		framed: newFramed(),
		lb:     make([]byte, 2),
	}
}

func (fr *Reader) EnableBigFrames() {
	fr.framed.EnableBigFrames()
	fr.lb = make([]byte, 4)
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{Stream: w, framed: newFramed()}
}

func NewReadWriteCloser(rwc io.ReadWriteCloser) *ReadWriteCloser {
	return &ReadWriteCloser{
		*NewReader(rwc),
		*NewWriter(rwc),
		rwc,
	}
}

func (fr *ReadWriteCloser) EnableBigFrames() {
	fr.Reader.EnableBigFrames()
	fr.Writer.EnableBigFrames()
}

func (fr *ReadWriteCloser) DisableThreadSafety() {
	fr.Reader.DisableThreadSafety()
	fr.Writer.DisableThreadSafety()
}

// EnableBuffering enables buffering of read data
func (fr *Reader) EnableBuffering(size int) {
	fr.mutex.Lock()
	fr.Stream = bufio.NewReaderSize(fr.Stream, size+fr.headerLength)
	fr.mutex.Unlock()
}

/*
Read implements the function from io.Reader.  Unlike io.Reader.Read,
frame.Read only returns full frames of data (assuming that the data was written
by a fr.Writer).
*/
func (fr *Reader) Read(buffer []byte) (n int, err error) {
	if !fr.threadSafetyDisabled {
		fr.mutex.Lock()
		defer fr.mutex.Unlock()
	}

	n, err = fr.readLength()
	if err != nil {
		return
	}

	bufferSize := len(buffer)
	if n > bufferSize {
		return 0, fmt.Errorf("Buffer of size %d is too small to hold frame of size %d", bufferSize, n)
	}

	// Read into buffer
	n, err = io.ReadFull(fr.Stream, buffer[:n])
	return
}

// ReadFrame reads the next frame, using a new buffer sized to hold the frame.
func (fr *Reader) ReadFrame() (frame []byte, err error) {
	if !fr.threadSafetyDisabled {
		fr.mutex.Lock()
		defer fr.mutex.Unlock()
	}

	var n int
	n, err = fr.readLength()
	if err != nil {
		return
	}

	frame = make([]byte, n)

	// Read into buffer
	_, err = io.ReadFull(fr.Stream, frame)
	return
}

func (fr *Reader) readLength() (int, error) {
	_, err := io.ReadFull(fr.Stream, fr.lb)
	if err != nil {
		return 0, err
	}
	if fr.bigFramesEnabled {
		return int(endianness.Uint32(fr.lb)), nil
	}
	return int(endianness.Uint16(fr.lb)), nil
}

/*
Write implements the Write method from io.Writer.  It prepends a frame length
header that allows the fr.Reader on the other end to read the whole frame.
*/
func (fr *Writer) Write(frame []byte) (n int, err error) {
	if !fr.threadSafetyDisabled {
		fr.mutex.Lock()
		defer fr.mutex.Unlock()
	}

	n = len(frame)
	if n, err = fr.writeHeaderLength(n); err != nil {
		return
	}

	// Write the data
	var written int
	if written, err = fr.Stream.Write(frame); err != nil {
		return
	}
	if written != n {
		err = fmt.Errorf("%d bytes written, expected to write %d", written, n)
	}
	return
}

// WriteAtomic writes a the frame and its length header in a single write. This requires
// that the frame was read into a buffer obtained from a pool created with
// NewHeaderPreservingBufferPool().
func (fr *Writer) WriteAtomic(frame bpool.ByteSlice) (n int, err error) {
	if !fr.threadSafetyDisabled {
		fr.mutex.Lock()
		defer fr.mutex.Unlock()
	}

	n = len(frame.Bytes())
	_frame := frame.BytesWithHeader()

	switch fr.bigFramesEnabled {
	case true:
		endianness.PutUint32(_frame, uint32(n))
	default:
		endianness.PutUint16(_frame, uint16(n))
	}

	// Write frame and data atomically
	_, err = fr.Stream.Write(_frame)
	if err != nil {
		n = 0
	}
	return
}

func (fr *Writer) WritePieces(pieces ...[]byte) (n int, err error) {
	if !fr.threadSafetyDisabled {
		fr.mutex.Lock()
		defer fr.mutex.Unlock()
	}

	for _, piece := range pieces {
		n = n + len(piece)
	}

	if n, err = fr.writeHeaderLength(n); err != nil {
		return
	}

	// Write the data
	var written int
	for _, piece := range pieces {
		var nw int
		if nw, err = fr.Stream.Write(piece); err != nil {
			return
		}
		written = written + nw
	}
	if written != n {
		err = fmt.Errorf("%d bytes written, expected to write %d", written, n)
	}
	return
}

func (fr *Writer) writeHeaderLength(n int) (int, error) {
	if int64(n) > fr.maxFrameLength {
		return 0, fmt.Errorf(tooLongError, n, MaxFrameLength)
	}

	if fr.bigFramesEnabled {
		return n, binary.Write(fr.Stream, endianness, uint32(n))
	}
	return n, binary.Write(fr.Stream, endianness, uint16(n))
}

// NewHeaderPreservingBufferPool creates a BufferPool that leaves room at the beginning
// of buffers for the framed header. This allows use of the WriteAtomic() capability.
func NewHeaderPreservingBufferPool(maxSize int, width int, enableBigFrames bool) bpool.ByteSlicePool {
	headerLength := FrameHeaderLength
	if enableBigFrames {
		headerLength = FrameHeaderLengthBig
	}
	return bpool.NewHeaderPreservingByteSlicePool(maxSize/(width+headerLength), width, headerLength)
}
