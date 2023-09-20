// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcreconciler

import (
	"context"
	"net"

	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// DpcReconciler should translate the currently selected Device port configuration
// (DevicePortConfig struct; abbreviated to DPC) into the corresponding low-level
// network configuration of the target network stack and apply it using the Reconciler
// (see libs/reconciler).
// It is not required for DpcReconciler to be thread-safe.
type DpcReconciler interface {
	// Reconcile : call to apply the current DPC into the target network stack.
	// Synchronous configuration operations are run from within the caller's Go routine.
	Reconcile(ctx context.Context, args Args) ReconcileStatus
}

// Args : a high-level device configuration received from the controller, further translated
// by DpcReconciler into the corresponding low-level network configuration and applied into
// the target network stack.
type Args struct {
	DPC types.DevicePortConfig
	AA  types.AssignableAdapters
	RS  types.RadioSilence
	GCP types.ConfigItemValueMap
}

// ReconcileStatus : state data related to config reconciliation.
type ReconcileStatus struct {
	// Error summarizing the outcome of the reconciliation.
	Error error
	// True if any async operations are in progress.
	AsyncInProgress bool
	// ResumeReconcile channel is used by DpcReconciler to signal that reconciliation
	// should be triggered (even if Args has not necessarily changed). This is either
	// because some config operation was running asynchronously and has just finalized
	// (and should be followed up on), or because something changed in the current state
	// that DpcReconciler needs to reflect in the applied config.
	ResumeReconcile <-chan struct{}
	// CancelAsyncOps : send cancel signal to all asynchronously running operations.
	CancelAsyncOps func()
	// WaitForAsyncOps : wait for all asynchronously running operations to complete.
	WaitForAsyncOps func()
	// The set of configuration items currently in a failed state.
	// Includes information about the last (failed) operation.
	FailingItems reconciler.OperationLog
	// Radio silence state information.
	RS types.RadioSilence
	// Status of domain name system (DNS) configuration.
	// Not to be confused with device network status
	// (which DPC reconciler does not work with).
	DNS DNSStatus
	// XXX Add more as needed...
}

// DNSStatus : state information related to domain name system (DNS).
type DNSStatus struct {
	// Non-nil if reconciler failed to apply DNS configuration.
	Error error
	// Configured DNS servers sorted by physical interface name.
	Servers map[string][]net.IP // interface name -> DNS servers
}
