// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"os"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// UnsupportedHandler is common handler for filesystems which not support encryption
type UnsupportedHandler struct {
	log *base.LogObject
}

// GetOperationalInfo returns status of encryption and string with information
func (h *UnsupportedHandler) GetOperationalInfo() (info.DataSecAtRestStatus, string) {
	return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
		"Current filesystem does not support encryption"
}

// SetHandlerOptions is dummy for UnsupportedHandler
func (h *UnsupportedHandler) SetHandlerOptions(_ HandlerOptions) {}

// GetVaultStatuses returns statuses of vault(s)
func (h *UnsupportedHandler) GetVaultStatuses() []*types.VaultStatus {
	status := types.VaultStatus{}
	status.Name = types.DefaultVaultName
	status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED
	status.SetErrorDescription(types.ErrorDescription{Error: "Unsupported filesystem"})
	return []*types.VaultStatus{&status}
}

// SetupDeprecatedVaults is dummy for UnsupportedHandler
func (h *UnsupportedHandler) SetupDeprecatedVaults() error {
	return nil
}

// SetupDefaultVault creates directory for UnsupportedHandler
func (h *UnsupportedHandler) SetupDefaultVault() error {
	_, err := os.Stat(defaultVault)
	if os.IsNotExist(err) {
		// No TPM or TPM lacks required features
		// Vault is just a plain folder in those cases
		return os.MkdirAll(defaultVault, 755)
	}
	return nil
}

// RemoveDefaultVault is dummy for UnsupportedHandler
func (h *UnsupportedHandler) RemoveDefaultVault() error {
	return nil
}

// UnlockDefaultVault unlocks vault from zfs
func (h *UnsupportedHandler) UnlockDefaultVault() error {
	return nil
}
