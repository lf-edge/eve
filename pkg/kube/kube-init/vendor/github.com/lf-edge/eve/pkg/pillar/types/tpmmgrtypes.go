// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// TpmSanityStatus is used to report TPM status after some runtime
// sanity checks
type TpmSanityStatus struct {
	Name   string
	Status MaintenanceModeReason
	ErrorAndTime
}

// Key returns name for the TpmSanityStatus
func (status TpmSanityStatus) Key() string {
	return status.Name
}
