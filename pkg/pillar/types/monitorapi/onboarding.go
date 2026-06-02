// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

import uuid "github.com/satori/go.uuid"

// OnboardingStatus reports whether the device has been onboarded to a
// controller and, if so, its assigned identity.
type OnboardingStatus struct {
	// DeviceUUID is the controller-assigned device identity. The zero UUID
	// means the device is not yet onboarded.
	DeviceUUID uuid.UUID `json:"deviceUuid"`
	// HardwareModel as reported by the controller.
	HardwareModel string `json:"hardwareModel"`
}
