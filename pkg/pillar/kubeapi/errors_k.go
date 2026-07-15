// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"errors"
	"fmt"
	"net"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// transientf builds a TransientError from a formatted message. Use it for
// failure modes that carry no typed Kubernetes error to classify -- the
// cluster-storage stack's own "not ready yet" diagnostics (virtctl/CDI upload,
// Longhorn engine not deployed) -- so the transient verdict is stated explicitly
// by the code rather than re-derived from message text downstream.
func transientf(format string, args ...interface{}) error {
	return &TransientError{Err: fmt.Errorf(format, args...)}
}

// asTransient classifies a Kubernetes client-go error and wraps it in a
// TransientError when it is retryable, or returns err unchanged when it is
// permanent. Classification is by typed error (or a net.Error for a request
// that never reached the API server), never by message text, so it does not
// break on a Kubernetes version bump. Returns nil for a nil error.
func asTransient(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case k8serrors.IsAlreadyExists(err),
		k8serrors.IsInvalid(err),
		k8serrors.IsBadRequest(err),
		k8serrors.IsForbidden(err),
		k8serrors.IsUnauthorized(err):
		// Permanent: reissuing the same request cannot succeed.
		return err
	case k8serrors.IsNotFound(err),
		k8serrors.IsTimeout(err),
		k8serrors.IsServerTimeout(err),
		k8serrors.IsTooManyRequests(err),
		k8serrors.IsServiceUnavailable(err),
		k8serrors.IsInternalError(err):
		// Transient: a storageclass/CRD/service not registered yet, or the
		// API server briefly unavailable while the cluster comes up.
		return &TransientError{Err: err}
	}
	// Not a typed API-status error: a dial/connection failure before the
	// request reached the API server (k3s still starting) shows up as a
	// net.Error, which is also transient.
	var netErr net.Error
	if errors.As(err, &netErr) {
		return &TransientError{Err: err}
	}
	return err
}
