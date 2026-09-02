// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
)

// VaultUnlockMethod.ToProto is a plain cast, so it stays correct only while the
// info.VaultUnlockMethod values are numbered to match. Pin the pairing here:
// renumbering either side must fail rather than silently mislabel a fleet report.
func TestVaultUnlockMethodToProto(t *testing.T) {
	cases := map[VaultUnlockMethod]info.VaultUnlockMethod{
		VaultUnlockNone:           info.VaultUnlockMethod_VAULT_UNLOCK_METHOD_UNSPECIFIED,
		VaultUnlockTPMLocalSealed: info.VaultUnlockMethod_VAULT_UNLOCK_METHOD_TPM_LOCAL_SEALED,
		VaultUnlockControllerKey:  info.VaultUnlockMethod_VAULT_UNLOCK_METHOD_CONTROLLER_KEY,
		VaultUnlockNoTPM:          info.VaultUnlockMethod_VAULT_UNLOCK_METHOD_NO_TPM,
		VaultUnlockRecreated:      info.VaultUnlockMethod_VAULT_UNLOCK_METHOD_RECREATED,
	}
	for in, want := range cases {
		assert.Equal(t, want, in.ToProto(), "unlock method %s", in)
	}
	// Every pillar value must be covered, so a value added later cannot be
	// forgotten here and silently report as unspecified.
	assert.Len(t, cases, int(VaultUnlockRecreated)+1)
}

// VaultKeyDerivation.ToProto is a plain cast, pinned here for the same reason as
// TestVaultUnlockMethodToProto: renumbering either side must fail rather than
// silently mislabel which devices still mix the fixed constant into the key.
func TestVaultKeyDerivationToProto(t *testing.T) {
	cases := map[VaultKeyDerivation]info.VaultKeyDerivation{
		VaultKeyDerivationNone:           info.VaultKeyDerivation_VAULT_KEY_DERIVATION_UNSPECIFIED,
		VaultKeyDerivationTPMOnly:        info.VaultKeyDerivation_VAULT_KEY_DERIVATION_TPM_ONLY,
		VaultKeyDerivationTPMAndConstant: info.VaultKeyDerivation_VAULT_KEY_DERIVATION_TPM_AND_CONSTANT,
	}
	for in, want := range cases {
		assert.Equal(t, want, in.ToProto(), "key derivation %s", in)
	}
	assert.Len(t, cases, int(VaultKeyDerivationTPMAndConstant)+1)
}
