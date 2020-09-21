package store

import (
	"context"
	"io"

	"github.com/containerd/containerd/content"
	"github.com/opencontainers/go-digest"
)

// PassthroughWriter takes an input stream and passes it through to an underlying writer,
// while providing the ability to manipulate the stream before it gets passed through
type PassthroughWriter struct {
	writer             content.Writer
	pipew              *io.PipeWriter
	digester           digest.Digester
	size               int64
	underlyingDigester digest.Digester
	underlyingSize     int64
	// Reader reader that the go routine should read from to get data to process
	Reader *io.PipeReader
	// Done channel for go routine to indicate when it is done. If it does not,
	// it might block forever
	Done chan bool
}

func NewPassthroughWriter(writer content.Writer, f func(pw *PassthroughWriter)) content.Writer {
	r, w := io.Pipe()
	pw := &PassthroughWriter{
		writer:             writer,
		pipew:              w,
		digester:           digest.Canonical.Digester(),
		underlyingDigester: digest.Canonical.Digester(),
		Reader:             r,
		Done:               make(chan bool, 1),
	}
	go f(pw)
	return pw
}

func (pw *PassthroughWriter) Write(p []byte) (n int, err error) {
	n, err = pw.pipew.Write(p)
	pw.digester.Hash().Write(p[:n])
	pw.size += int64(n)
	return
}

func (pw *PassthroughWriter) Close() error {
	pw.pipew.Close()
	pw.writer.Close()
	return nil
}

// Digest may return empty digest or panics until committed.
func (pw *PassthroughWriter) Digest() digest.Digest {
	return pw.digester.Digest()
}

// Commit commits the blob (but no roll-back is guaranteed on an error).
// size and expected can be zero-value when unknown.
// Commit always closes the writer, even on error.
// ErrAlreadyExists aborts the writer.
func (pw *PassthroughWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	pw.pipew.Close()
	_ = <-pw.Done
	pw.Reader.Close()
	return pw.writer.Commit(ctx, pw.underlyingSize, pw.underlyingDigester.Digest(), opts...)
}

// Status returns the current state of write
func (pw *PassthroughWriter) Status() (content.Status, error) {
	return pw.writer.Status()
}

// Truncate updates the size of the target blob
func (pw *PassthroughWriter) Truncate(size int64) error {
	return pw.writer.Truncate(size)
}

// UnderlyingWrite write to the underlying writer
func (pw *PassthroughWriter) UnderlyingWrite(p []byte) error {
	if _, err := pw.writer.Write(p); err != nil {
		return err
	}
	pw.underlyingSize += int64(len(p))
	pw.underlyingDigester.Hash().Write(p)
	return nil
}
