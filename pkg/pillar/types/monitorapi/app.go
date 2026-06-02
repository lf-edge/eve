// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import uuid "github.com/satori/go.uuid"

// AppsList is the full set of application instances on the device. The TUI
// derives any aggregate counts it needs from this list.
type AppsList struct {
	Instances []AppInstance `json:"instances,omitempty"`
}

// AppInstance is a single application instance.
type AppInstance struct {
	UUID    uuid.UUID `json:"uuid"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	State   SwState   `json:"state"`
	// Error is the current error for the instance, empty if none.
	Error string `json:"error"`
}

// SwState is the lifecycle state of a downloadable/runnable object
// (app instance, volume, content).
type SwState string

// SwState enumerates the object lifecycle states.
const (
	SwStateInitial              SwState = "initial"
	SwStateResolvingTag         SwState = "resolvingTag"
	SwStateResolvedTag          SwState = "resolvedTag"
	SwStateDownloading          SwState = "downloading"
	SwStateDownloaded           SwState = "downloaded"
	SwStateVerifying            SwState = "verifying"
	SwStateVerified             SwState = "verified"
	SwStateLoading              SwState = "loading"
	SwStateLoaded               SwState = "loaded"
	SwStateCreatingVolume       SwState = "creatingVolume"
	SwStateCreatedVolume        SwState = "createdVolume"
	SwStateInstalled            SwState = "installed"
	SwStateAwaitNetworkInstance SwState = "awaitNetworkInstance"
	SwStateStartDelayed         SwState = "startDelayed"
	SwStateBooting              SwState = "booting"
	SwStateRunning              SwState = "running"
	SwStatePausing              SwState = "pausing"
	SwStatePaused               SwState = "paused"
	SwStateHalting              SwState = "halting"
	SwStateHalted               SwState = "halted"
	SwStateBroken               SwState = "broken"
	SwStateUnknown              SwState = "unknown"
	SwStatePending              SwState = "pending"
	SwStateScheduling           SwState = "scheduling"
	SwStateFailed               SwState = "failed"
	SwStateRemoteLoaded         SwState = "remoteLoaded"
)
