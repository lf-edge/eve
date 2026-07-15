// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeapi

import "errors"

// TransientError marks a cluster-storage failure that is expected to clear once
// the EVE-k storage stack (the k3s API server, Longhorn and CDI) has finished
// coming up -- e.g. during a freshly installed node's first boot or the minutes
// after a kvm->k conversion. Callers use IsTransient to decide whether a parked
// volume-create is worth re-driving; a permanent failure must not be retried in
// a loop. The verdict is recorded at the point the typed Kubernetes error is
// still available, because it is lost once the error is flattened to a string
// across the volumemgr worker boundary.
//
// This type and IsTransient are build-tag-free so volumemgr can consult the
// verdict on every hypervisor; the classification that produces a TransientError
// (asTransient/transientf) is EVE-k only and lives in the k-tagged file.
type TransientError struct {
	Err error
}

// Error implements the error interface.
func (e *TransientError) Error() string { return e.Err.Error() }

// Unwrap lets errors.Is/errors.As reach the wrapped error.
func (e *TransientError) Unwrap() error { return e.Err }

// IsTransient reports whether err, or anything it wraps, was classified as a
// transient cluster-storage failure. Safe on a nil error (returns false). On
// non-EVE-k builds nothing produces a TransientError, so it always returns false.
func IsTransient(err error) bool {
	var t *TransientError
	return errors.As(err, &t)
}
