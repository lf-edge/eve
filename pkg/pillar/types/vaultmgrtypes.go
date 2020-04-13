// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/api/go/info"
)

//VaultStatus represents running status of a Vault
type VaultStatus struct {
	Name   string
	Status info.DataSecAtRestStatus
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

//Key returns the key used for indexing into a list of vaults
func (status VaultStatus) Key() string {
	return status.Name
}
