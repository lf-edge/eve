package http

import (
	"io"
	"time"
)

// TimeoutReader reads until a preset timeout,
// then returns a timeout error.
// The timeout is for each read.
type TimeoutReader struct {
	timeout time.Duration
	reader  io.Reader
}

// NewTimeoutReader creates a new TimeoutReader.
func NewTimeoutReader(timeout time.Duration, r io.Reader) *TimeoutReader {
	return &TimeoutReader{timeout, r}
}

// Read reads from the underlying reader.
func (r *TimeoutReader) Read(p []byte) (int, error) {
	// channel is just used to signal when the read is done
	var (
		n   int
		err error
	)
	c := make(chan byte, 1)
	// we have to put this in a goroutine, so we do not block our main routine
	// waiting on it
	go func() {
		n, err = r.reader.Read(p)
		c <- 0
	}()

	timer := time.NewTimer(r.timeout)
	defer timer.Stop()

	select {
	case <-c:
		return n, err
	case <-timer.C:
		return 0, &ErrTimeout{}
	}
}

// ErrTimeout is the error returned when a timeout occurs. The error message
// will be the timeout duration that was exceeded.
type ErrTimeout struct {
	timeout time.Duration
}

func (e *ErrTimeout) Error() string {
	return e.timeout.String()
}

// Is the other error the same type? We do not really care about the properties
func (e *ErrTimeout) Is(err error) bool {
	_, ok := err.(*ErrTimeout)
	return ok
}
