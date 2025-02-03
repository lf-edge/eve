// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/canonical/go-tpm2"
	"golang.org/x/sys/unix"
)

const (
	maxCommandSize int = 4096
)

type timeoutError struct{}

func (e timeoutError) Error() string { return "i/o timeout" }
func (e timeoutError) Timeout() bool { return true }

// Tcti represents a connection to a Linux TPM character device.
type Tcti struct {
	name   string
	closer io.Closer
	conn   syscall.RawConn
	rsp    *bytes.Reader

	timeout time.Duration
}

func (d *Tcti) wrapErr(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if err == errClosed {
		err = os.ErrClosed
	}
	return &os.PathError{
		Op:   op,
		Path: d.name,
		Err:  err}
}

func (d *Tcti) pollReadyToRead() error {
	var timeout *unix.Timespec
	if d.timeout != tpm2.InfiniteTimeout {
		timeout = new(unix.Timespec)
		*timeout = unix.NsecToTimespec(int64(d.timeout))
	}

	var pollErr error
	if err := d.conn.Control(func(fd uintptr) {
		pollErr = func() error {
			fds := []unix.PollFd{unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Ppoll(fds, timeout, nil)
			if err != nil {
				return err
			}
			if n == 0 {
				return timeoutError{}
			}
			if fds[0].Events != fds[0].Revents {
				return fmt.Errorf("invalid revents: %d", fds[0].Revents)
			}
			return nil
		}()
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return d.wrapErr("poll", errClosed)
	}

	return d.wrapErr("poll", pollErr)
}

func (d *Tcti) read(data []byte) (n int, err error) {
	var readErr error
	if err := d.conn.Read(func(fd uintptr) bool {
		n, readErr = syscall.Read(int(fd), data)
		return true
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return 0, d.wrapErr("read", errClosed)
	}

	if n == 0 && readErr == nil {
		readErr = io.EOF
	}
	return n, d.wrapErr("read", readErr)
}

func (d *Tcti) readNextResponse() error {
	// Note that the TPM character device read and poll implementations are a bit funky.
	// read() can return 0 instead of -EWOULDBLOCK if a response is not ready. This is
	// problematic because go's netpoller tries a read before deciding whether to park
	// the current routine and waking it when it later becomes ready to read, and this
	// causes it just immediately returning io.EOF.
	//
	// To work around this, we do our own poll / read dance, but even this doesn't work
	// as expected in practise.
	//
	// read() can also block until the current command completes even in non-blocking
	// mode if we call it whilst the kernel TPM async worker is dispatching the command,
	// because it takes a lock held by the worker, so we don't try it before polling.
	//
	// However, poll() will block until the current command completes if we call it whilst
	// the kernel worker is dispatching the command, ignoring any timeout, because it
	// takes a lock held by the worker.
	if err := d.pollReadyToRead(); err != nil {
		return err
	}

	buf := make([]byte, maxCommandSize)
	n, err := d.read(buf)
	if err != nil {
		return err
	}

	d.rsp = bytes.NewReader(buf[:n])
	return nil
}

// Read implmements [tpm2.TCTI].
func (d *Tcti) Read(data []byte) (int, error) {
	if d.rsp == nil {
		// Newer kernels support partial reads, but there is no way to detect
		// for this support from userspace, so always read responses in a single
		// call.
		if err := d.readNextResponse(); err != nil {
			return 0, err
		}
	}

	n, err := d.rsp.Read(data)
	if err == io.EOF {
		d.rsp = nil
	}
	return n, err
}

// Write implmements [tpm2.TCTI].
func (d *Tcti) Write(data []byte) (int, error) {
	if d.rsp != nil {
		// Don't start a new command before the previous response has been fully read.
		// This doesn't catch the case where we haven't fetched the previous response
		// from the device, but the subsequent write will fail with -EBUSY
		return 0, d.wrapErr("write", errors.New("unread bytes from previous response"))
	}

	var n int
	var writeErr error
	if err := d.conn.Write(func(fd uintptr) bool {
		n, writeErr = syscall.Write(int(fd), data)
		return true
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return 0, d.wrapErr("write", errClosed)
	}

	if n < len(data) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	return n, d.wrapErr("write", writeErr)
}

// Close implements [tpm2.TCTI.Close].
func (d *Tcti) Close() error {
	return d.closer.Close()
}

// SetTimeout implements [tpm2.TCTI.SetTimeout].
func (d *Tcti) SetTimeout(timeout time.Duration) error {
	d.timeout = timeout
	return nil
}

// MakeSticky implements [tpm2.TCTI.MakeSticky].
func (d *Tcti) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return errors.New("not implemented")
}
