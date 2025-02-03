// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"errors"
	"time"
)

// InfiniteTimeout can be used to configure an infinite timeout.
const InfiniteTimeout = -1 * time.Millisecond

// ErrTimeoutNotSupported indicates that a [TCTI] implementation does not support
// configuring the command timeout.
var ErrTimeoutNotSupported = errors.New("configurable command timeouts are not supported")

// XXX: Note that the "TCG TSS 2.0 TPM Command Transmission Interface (TCTI) API Specification"
// defines the following callbacks:
// - transmit, which is equivalent to io.Writer.
// - receive, which is equivalent to io.Reader, although that lacks the ability to specify
//   a timeout.
// - finalize, which is equivalent to io.Closer.
// - cancel, which we don't implement at the moment, and the Linux character device doesn't
//   support cancellation anyway.
// - getPollHandles, doesn't really make sense here because go's runtime does the polling on
//   Read.
// - setLocality, makes no sense in this package.
// - makeSticky, not implemented yet by any TCTI implementation in tss2 AFAICT.

// TCTI represents a communication channel to a TPM implementation.
type TCTI interface {
	// Read is used to receive a response to a previously transmitted command. The implementation
	// must support partial reading of a response, and must return io.EOF when there are no more
	// bytes of a response left to read.
	//
	// Reads can block and should consider the previously configured timeout. Once a response
	// has been received from the device and when part of the response is read from this interface,
	// subsequent reads to obtain the rest of the response should not block.
	Read(p []byte) (int, error)

	// Write is used to transmit a serialized command to the TPM implementation. Commands are
	// written in a single write. Writes should be non blocking.
	Write(p []byte) (int, error)

	Close() error

	// SetTimeout sets the amount of time to wait before Read times out. Set to InfiniteTimeout to
	// never time out.
	SetTimeout(timeout time.Duration) error

	// MakeSticky requests that the underlying resource manager does not unload the resource
	// associated with the supplied handle between commands.
	MakeSticky(handle Handle, sticky bool) error
}
