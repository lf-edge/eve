// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
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

// FormatMismatchingPCRs

func TestFormatMismatchingPCRs(t *testing.T) {
	// No mismatching PCRs → empty string so callers can omit the clause
	assert.Equal(t, "", FormatMismatchingPCRs(nil))
	assert.Equal(t, "", FormatMismatchingPCRs([]int{}))

	// Known mismatching PCRs → descriptive clause with the "possibly" qualifier
	assert.Equal(t, "possibly mismatching PCR indexes [4 8 9 13 14]",
		FormatMismatchingPCRs([]int{4, 8, 9, 13, 14}))
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

// VaultStatus / EncryptedVaultKeyFromDevice / EncryptedVaultKeyFromController LogCreate / LogModify / LogDelete

func TestVaultStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	s := VaultStatus{Name: "vault1"}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}

func TestEncryptedVaultKeyFromDeviceLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	k := EncryptedVaultKeyFromDevice{Name: "default"}
	k.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	k.LogModify(log, k)
	k.LogDelete(log)
}

func TestEncryptedVaultKeyFromControllerLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	k := EncryptedVaultKeyFromController{Name: "ctrl-vault"}
	k.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	k.LogModify(log, k)
	k.LogDelete(log)
}

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
