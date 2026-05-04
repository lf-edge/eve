// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
)

// VaultStatus.IsVaultInError

func TestVaultStatusIsVaultInError(t *testing.T) {
	// No error status → false
	s := VaultStatus{Status: info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED}
	assert.False(t, s.IsVaultInError())

	// Error status but no mismatching PCRs → false
	s.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
	assert.False(t, s.IsVaultInError())

	// Error status with mismatching PCRs → true
	s.MismatchingPCRs = []int{0, 1, 7}
	assert.True(t, s.IsVaultInError())
}

// VaultConfig / VaultStatus / EncryptedVaultKeyFromDevice / EncryptedVaultKeyFromController Key / LogKey

func TestVaultConfigKey(t *testing.T) {
	assert.Equal(t, "global", VaultConfig{}.Key())
}

func TestVaultStatusLogKey(t *testing.T) {
	s := VaultStatus{Name: "vault1"}
	assert.Equal(t, "vault1", s.Key())
	assert.Contains(t, s.LogKey(), "vault1")
}

func TestEncryptedVaultKeyFromDeviceLogKey(t *testing.T) {
	k := EncryptedVaultKeyFromDevice{Name: "default"}
	assert.Equal(t, "default", k.Key())
	assert.Contains(t, k.LogKey(), "default")
}

func TestEncryptedVaultKeyFromControllerLogKey(t *testing.T) {
	k := EncryptedVaultKeyFromController{Name: "ctrl-vault"}
	assert.Equal(t, "ctrl-vault", k.Key())
	assert.Contains(t, k.LogKey(), "ctrl-vault")
}
