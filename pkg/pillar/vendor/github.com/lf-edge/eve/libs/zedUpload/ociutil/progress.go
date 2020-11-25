package ociutil

import (
	"io"
)

// ProgressWriter is a writer which will send the download progress
type ProgressWriter struct {
	w              io.Writer
	updates        chan<- Update
	size, complete int64
}

// Write write bytes and update the progress channel.
// Returns number of bytes written and error, if any
func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n, err := pw.w.Write(p)
	if err != nil {
		return n, err
	}

	pw.complete += int64(n)
	// if our provides total size is 0, then we allow anything, so send a "Total"
	// of the same amount as Complete
	totalSize := pw.size
	if totalSize == 0 {
		totalSize = pw.complete
	}

	pw.updates <- Update{
		Total:    totalSize,
		Complete: pw.complete,
	}

	return n, err
}

// Error set an error
func (pw *ProgressWriter) Error(err error) error {
	pw.updates <- Update{
		Total:    pw.size,
		Complete: pw.complete,
		Error:    err,
	}
	return err
}

// Close close the writer
func (pw *ProgressWriter) Close() error {
	pw.updates <- Update{
		Total:    pw.size,
		Complete: pw.complete,
		Error:    io.EOF,
	}
	return io.EOF
}

// Update represents an update to send on a channel
type Update struct {
	Total    int64
	Complete int64
	Error    error
}
