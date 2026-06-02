// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// VaultStatus is the data-at-rest encryption (vault) state, interpreted from
// EVE's raw status by the Go mapper into a tagged union the TUI shows directly.
//
//monitorapi:union tag=state
type VaultStatus interface{ isVaultStatus() }

// VaultUnknown — vault state not yet determined.
type VaultUnknown struct{}

// VaultDisabled — encryption available but not in use.
type VaultDisabled struct {
	TPMUsed bool   `json:"tpmUsed"`
	Error   string `json:"error"`
}

// VaultUnlocked — encryption enabled and the vault is unlocked.
type VaultUnlocked struct {
	TPMUsed bool `json:"tpmUsed"`
}

// VaultLocked — encryption enabled but the vault could not be unlocked.
type VaultLocked struct {
	Error string `json:"error"`
	// MismatchingPCRs lists the PCR indices that no longer match (sealed-key
	// case); empty otherwise.
	MismatchingPCRs []uint32 `json:"mismatchingPcrs,omitempty"`
}

func (VaultUnknown) isVaultStatus()  {}
func (VaultDisabled) isVaultStatus() {}
func (VaultUnlocked) isVaultStatus() {}
func (VaultLocked) isVaultStatus()   {}
