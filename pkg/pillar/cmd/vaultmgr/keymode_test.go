// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
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

// A recorded mode is where unlocking starts. It is not treated as a fact --
// the handler falls back to the other derivation -- but it is what gets tried
// first, so a device that has one never pays for a wrong first guess.
func TestVaultKeyModeUsesThePersistedConfig(t *testing.T) {
	initTest(t)
	for _, tpmKeyOnly := range []bool{true, false} {
		vaultConfig = types.VaultConfig{TpmKeyOnly: tpmKeyOnly}
		vaultConfigInited = true
		assert.Equal(t, tpmKeyOnly, vaultKeyMode())
	}
}

// With no recorded mode, the derivation a vault created today is keyed with is
// the one to try first. It is wrong for a pre-7.10.0 merged-key vault whose
// config was lost, which is exactly what the unlock fallback covers.
func TestVaultKeyModeWithoutAPersistedConfig(t *testing.T) {
	initTest(t)
	// A value the persisted-config branch would return, so dropping the branch
	// check below shows up as the wrong answer rather than as a coincidence.
	vaultConfig = types.VaultConfig{TpmKeyOnly: false}
	vaultConfigInited = false
	assert.True(t, vaultKeyMode())
}

func TestKeyDerivationOf(t *testing.T) {
	assert.Equal(t, types.VaultKeyDerivationTPMOnly, keyDerivationOf(true))
	assert.Equal(t, types.VaultKeyDerivationTPMAndConstant, keyDerivationOf(false))
}

// fakeHandler reports a resolved key mode and nothing else; recordVaultKeyMode
// reaches no other part of the interface.
type fakeHandler struct {
	vault.Handler
	options vault.HandlerOptions
}

func (h fakeHandler) GetHandlerOptions() vault.HandlerOptions {
	return h.options
}

func setHandler(t *testing.T, h vault.Handler) {
	previous := handler
	handler = h
	t.Cleanup(func() { handler = previous })
}

// newKeyModeCtx returns a context whose VaultConfig publication is in memory,
// so what recordVaultKeyMode writes can be read back.
func newKeyModeCtx(t *testing.T, tpmEnabled bool) *vaultMgrContext {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VaultConfig{},
	})
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	return &vaultMgrContext{pubVaultConfig: pub, tpmEnabled: tpmEnabled}
}

func recordedKeyMode(t *testing.T, ctx *vaultMgrContext) (types.VaultConfig, bool) {
	t.Helper()
	item, err := ctx.pubVaultConfig.Get(types.VaultConfig{}.Key())
	if err != nil {
		return types.VaultConfig{}, false
	}
	config, ok := item.(types.VaultConfig)
	assert.True(t, ok, "VaultConfig publication holds %T", item)
	return config, true
}

// What gets recorded is the derivation that opened the vault, read off the
// handler. Recording the first guess instead is what made a lost mode
// permanent.
func TestRecordVaultKeyModeRecordsTheResolvedMode(t *testing.T) {
	initTest(t)
	setHandler(t, fakeHandler{options: vault.HandlerOptions{TpmKeyOnlyMode: true}})
	vaultConfigInited = false
	ctx := newKeyModeCtx(t, true)

	recordVaultKeyMode(ctx)

	config, recorded := recordedKeyMode(t, ctx)
	assert.True(t, recorded)
	assert.True(t, config.TpmKeyOnly)
	assert.True(t, vaultConfigInited)
}

// A recorded mode the vault no longer uses has to be overwritten. The vault
// recreate path is where the two come apart: it destroys the old vault and
// keys the replacement TPM-key-only, leaving whatever was recorded describing
// a vault that is gone. A boot that then trusted the record would start from
// the wrong derivation.
func TestRecordVaultKeyModeOverwritesAStaleMode(t *testing.T) {
	initTest(t)
	setHandler(t, fakeHandler{options: vault.HandlerOptions{TpmKeyOnlyMode: false}})
	vaultConfigInited = false
	ctx := newKeyModeCtx(t, true)
	recordVaultKeyMode(ctx)

	setHandler(t, fakeHandler{options: vault.HandlerOptions{TpmKeyOnlyMode: true}})
	recordVaultKeyMode(ctx)

	config, _ := recordedKeyMode(t, ctx)
	assert.True(t, config.TpmKeyOnly)
}

// Without a TPM the vault key is not derived from one, so there is no mode to
// record -- and none may be left behind for a later boot to read as its own.
func TestRecordVaultKeyModeSkipsWithoutTpm(t *testing.T) {
	initTest(t)
	setHandler(t, fakeHandler{options: vault.HandlerOptions{TpmKeyOnlyMode: true}})
	vaultConfigInited = false
	ctx := newKeyModeCtx(t, false)

	recordVaultKeyMode(ctx)

	_, recorded := recordedKeyMode(t, ctx)
	assert.False(t, recorded)
	assert.False(t, vaultConfigInited)
}
