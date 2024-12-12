// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// TpmSanityStatus is used to report TPM status after some runtime
// sanity checks
type TpmSanityStatus struct {
	Name   string
	Status int // TODO : add this to eve-api
	ErrorAndTime
}

func (status TpmSanityStatus) Key() string {
	return status.Name
}
