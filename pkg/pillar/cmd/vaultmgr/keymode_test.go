// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// initTest points the package logger at the test logger and restores the
// package-level vault config the functions under test read, so the order the
// tests run in cannot matter.
func initTest(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 0)
	config, inited := vaultConfig, vaultConfigInited
	t.Cleanup(func() {
		vaultConfig, vaultConfigInited = config, inited
	})
}

// A mode read back from the persisted vault config is authoritative: it is
// reported as-is and never flagged inferred, which is what keeps the handler
// from probing the other derivation behind it.
func TestVaultKeyModeUsesThePersistedConfig(t *testing.T) {
	initTest(t)
	for _, tpmKeyOnly := range []bool{true, false} {
		vaultConfig = types.VaultConfig{TpmKeyOnly: tpmKeyOnly}
		vaultConfigInited = true
		mode, inferred := vaultKeyMode()
		assert.Equal(t, tpmKeyOnly, mode)
		assert.False(t, inferred, "a persisted mode is not a guess")
	}
}

// Without a persisted config there is nothing that can identify the derivation
// an existing vault was created with, so whatever is inferred must be flagged
// as such regardless of the filesystem.
func TestVaultKeyModeFlagsAnInferredMode(t *testing.T) {
	initTest(t)
	// A value the persisted-config branch would return, so dropping the
	// branch check below shows up as a mode reported without the flag.
	vaultConfig = types.VaultConfig{TpmKeyOnly: true}
	vaultConfigInited = false
	_, inferred := vaultKeyMode()
	assert.True(t, inferred)
}
