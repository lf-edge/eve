// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// KubeInitAgentName is the pubsub agent name of the kube container's
// kube-init daemon.
const KubeInitAgentName = "kube-init"

// KubeInitUpdateStateFailed is the KubeInitStatus.UpdateState of a
// component update pass that failed and is not retried.
const KubeInitUpdateStateFailed = "failed"

// KubeInitUpdateStateDeferred is the KubeInitStatus.UpdateState of a
// component update pass that stopped, for a reason that can clear up on
// its own, and is run again later.
const KubeInitUpdateStateDeferred = "deferred"

// KubeInitUpdateStateNone is the KubeInitStatus.UpdateState when no
// component update pass has been started this boot.
const KubeInitUpdateStateNone = "none"

// KubeInitStatus is pillar's view of the status kube-init publishes about
// itself on its KubeInitStatus topic.
//
// kube-init lives in the kube container and is built as a separate Go
// module, so this is not the type it publishes: the two are coupled by
// topic name and JSON field names only. It mirrors the fields pillar
// uses from KubeInitStatus in
// pkg/kube/kube-init/kubeinitstatus/kubeinitstatus.go; a field renamed
// there must be renamed here.
//
// The topic is not persistent, so it never carries a value from an
// earlier boot.
type KubeInitStatus struct {
	// State is kube-init's FSM state (INIT, WAIT_UPGRADE, RUNNING, ...).
	State string
	// ComponentsReady is true once kube-init has reached RUNNING with
	// the kube component update pass of this boot over or not needed.
	ComponentsReady bool
	// UpdateState is none, in_progress, completed, failed or deferred
	// (stopped before changing anything, to be run again later).
	UpdateState string
	// UpdateError says why the pass failed or was deferred, empty
	// otherwise.
	UpdateError string
	// UpdatedAt is when kube-init took this snapshot.
	UpdatedAt time.Time
}

// Key is the key in pubsub.
func (KubeInitStatus) Key() string {
	return "global"
}

// ComponentPassOver reports whether kube-init is done changing the kube
// components for this boot: the update pass succeeded, was not needed,
// or failed for good. Until then the components may be mid-upgrade and
// their own readiness says little.
func (status KubeInitStatus) ComponentPassOver() bool {
	return status.ComponentsReady ||
		status.UpdateState == KubeInitUpdateStateFailed
}

// ComponentPassStarted reports whether kube-init has started a kube
// component update pass this boot, whatever has come of it since.
func (status KubeInitStatus) ComponentPassStarted() bool {
	return status.UpdateState != "" &&
		status.UpdateState != KubeInitUpdateStateNone
}
