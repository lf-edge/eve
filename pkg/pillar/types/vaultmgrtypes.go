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

//EncryptedVaultKeyFromDevice is published by vaultmgr towards Controller (through zedagent)
type EncryptedVaultKeyFromDevice struct {
	Name              string
	EncryptedVaultKey []byte
}

//Key returns name of the vault corresponding to this object
//for now it is only the default vault i.e. "Application Volume Store"
func (key EncryptedVaultKeyFromDevice) Key() string {
	return key.Name
}

//EncryptedVaultKeyFromController is published from Controller to vaultmgr (through zedagent)
type EncryptedVaultKeyFromController struct {
	Name              string
	EncryptedVaultKey []byte
}

//Key returns name of the vault corresponding to this object
//for now it is only the default vault i.e. "Application Volume Store"
func (key EncryptedVaultKeyFromController) Key() string {
	return key.Name
}
