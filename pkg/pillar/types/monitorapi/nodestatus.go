// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import uuid "github.com/satori/go.uuid"

// NodeStatus carries node-level identity and onboarding state for the summary
// view. It aggregates several internal sources (server config, onboarding
// status, EdgeNodeInfo, hardware serial), so it is assembled by the producer
// rather than mapped from a single internal type.
type NodeStatus struct {
	// Server is the controller address the node is configured to talk to.
	Server string `json:"server"`
	// NodeUUID is the controller-assigned device identity; the zero UUID
	// means the node is not yet onboarded.
	NodeUUID uuid.UUID `json:"nodeUuid"`
	// Onboarded reports whether onboarding has completed.
	Onboarded bool `json:"onboarded"`
	// NodeName is the controller-assigned device name (from EdgeNodeInfo);
	// empty until the node is onboarded and config is received.
	NodeName string `json:"nodeName"`
	// Serial is the hardware product serial number.
	Serial string `json:"serial"`
}
