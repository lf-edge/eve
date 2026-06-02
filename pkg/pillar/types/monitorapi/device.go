// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import uuid "github.com/satori/go.uuid"

// DeviceStatus is the node-level status snapshot shown by the TUI's summary
// view. It aggregates what EVE reports across several internal topics
// (onboarding, EdgeNodeInfo, hardware serial, zedagent lifecycle/attestation,
// vault) into one coherent message, assembled by the Go producer.
type DeviceStatus struct {
	// Identity / onboarding.
	Server        string    `json:"server"`
	NodeUUID      uuid.UUID `json:"nodeUuid"` // zero UUID until onboarded
	Onboarded     bool      `json:"onboarded"`
	NodeName      string    `json:"nodeName"`
	Serial        string    `json:"serial"`
	HardwareModel string    `json:"hardwareModel"`

	// Controller / lifecycle.
	ConfigStatus    ConfigGetStatus `json:"configStatus"`
	DeviceState     DeviceState     `json:"deviceState"`
	BootReason      BootReason      `json:"bootReason"`
	RebootReason    string          `json:"rebootReason"`
	MaintenanceMode bool            `json:"maintenanceMode"`

	// Attestation.
	AttestState AttestState `json:"attestState"`
	AttestError string      `json:"attestError"`

	// Data-at-rest encryption.
	Vault VaultStatus `json:"vault"`
}
