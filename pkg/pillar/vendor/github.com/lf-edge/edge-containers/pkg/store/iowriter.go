package store

import (
	"context"
	"io"

	"github.com/containerd/containerd/content"
	"github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"
)

type IoContentWriter struct {
	writer   io.Writer
	digester digest.Digester
	size     int64
}

// NewIoWriterWrapper wrap a simple io.Writer
func NewIoWriterWrapper(writer io.Writer, kind string) content.Writer {
	ioc := NewIoContentWriter(writer)
	return NewPassthroughWriter(ioc, func(pw *PassthroughWriter) {
		// write out the uncompressed data
		for {
			b := make([]byte, Blocksize, Blocksize)
			n, err := pw.Reader.Read(b)
			if err != nil && err != io.EOF {
				log.Errorf("WriterWrapper for %s: data read error: %v\n", kind, err)
				continue
			}
			l := n
			if n > len(b) {
				l = len(b)
			}

			if err := pw.UnderlyingWrite(b[:l]); err != nil {
				log.Errorf("WriterWrapper(%s): error writing to underlying writer: %v", kind, err)
				break
			}
			if err == io.EOF {
				break
			}
		}
		pw.Done <- true
	})
}

// NewIoContentWriter turn a plain io.Writer into a content.Writer
func NewIoContentWriter(writer io.Writer) content.Writer {
	return &IoContentWriter{
		writer:   writer,
		digester: digest.Canonical.Digester(),
	}
}

func (w *IoContentWriter) Write(p []byte) (n int, err error) {
	var (
		l int
	)
	if w.writer != nil {
		l, err = w.writer.Write(p)
		if err != nil {
			return 0, err
		}
	} else {
		l = len(p)
		// nothing to write
	}
	w.digester.Hash().Write(p[:l])
	w.size += int64(l)
	return
}

func (w *IoContentWriter) Close() error {
	return nil
}

// Digest may return empty digest or panics until committed.
func (w *IoContentWriter) Digest() digest.Digest {
	return w.digester.Digest()
}

// Commit commits the blob (but no roll-back is guaranteed on an error).
// size and expected can be zero-value when unknown.
// Commit always closes the writer, even on error.
// ErrAlreadyExists aborts the writer.
func (w *IoContentWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	return nil
}

// Status returns the current state of write
func (w *IoContentWriter) Status() (content.Status, error) {
	return content.Status{}, nil
}

// Truncate updates the size of the target blob
func (w *IoContentWriter) Truncate(size int64) error {
	return nil
}
