// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"errors"
	"fmt"
	"net"
	"testing"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var pvcGR = schema.GroupResource{Group: "", Resource: "persistentvolumeclaims"}

// TestAsTransientClassification checks that asTransient marks retryable
// cluster-storage failures transient and leaves permanent ones alone, driven by
// the typed Kubernetes error rather than message text.
func TestAsTransientClassification(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantTransient bool
	}{
		{"nil", nil, false},
		{"already-exists permanent", k8serrors.NewAlreadyExists(pvcGR, "p"), false},
		{"bad-request permanent", k8serrors.NewBadRequest("nope"), false},
		{"conflict unclassified permanent", k8serrors.NewConflict(pvcGR, "p", errors.New("x")), false},
		{"plain error permanent", errors.New("some local failure"), false},
		{"not-found transient", k8serrors.NewNotFound(pvcGR, "p"), true},
		{"service-unavailable transient", k8serrors.NewServiceUnavailable("cdi down"), true},
		{"internal transient", k8serrors.NewInternalError(errors.New("boom")), true},
		{"timeout transient", k8serrors.NewTimeoutError("slow", 1), true},
		{"too-many-requests transient", k8serrors.NewTooManyRequestsError("busy"), true},
		{"net dial error transient", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsTransient(asTransient(tc.err))
			if got != tc.wantTransient {
				t.Errorf("IsTransient(asTransient(%v)) = %v, want %v", tc.err, got, tc.wantTransient)
			}
		})
	}
}

// TestIsTransientThroughWrap verifies the verdict survives an additional
// fmt.Errorf %w wrap (as happens when csihandler wraps the kubeapi error before
// it crosses the worker boundary), and that wrapping a permanent error does not
// flip it to transient.
func TestIsTransientThroughWrap(t *testing.T) {
	transient := asTransient(k8serrors.NewServiceUnavailable("cdi down"))
	wrapped := fmt.Errorf("Error converting disk to PVC p: %w", transient)
	if !IsTransient(wrapped) {
		t.Errorf("wrapped transient error not detected as transient")
	}

	permanent := asTransient(k8serrors.NewBadRequest("nope"))
	wrappedPerm := fmt.Errorf("Error converting disk to PVC p: %w", permanent)
	if IsTransient(wrappedPerm) {
		t.Errorf("wrapped permanent error wrongly detected as transient")
	}
}

// TestTransientf checks the explicit-diagnostic constructor yields a transient
// error carrying the formatted message.
func TestTransientf(t *testing.T) {
	err := transientf("PVC Upload for pvc:%s attempts to upload image failed, no upload pod annotation", "p")
	if !IsTransient(err) {
		t.Errorf("transientf did not produce a transient error")
	}
	want := "PVC Upload for pvc:p attempts to upload image failed, no upload pod annotation"
	if err.Error() != want {
		t.Errorf("transientf message = %q, want %q", err.Error(), want)
	}
}
