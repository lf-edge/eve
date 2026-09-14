// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func testLog() *base.LogObject {
	logger := logrus.StandardLogger()
	return base.NewSourceLogObject(logger, "test", 0)
}

// unlockOnly returns an unlock func that accepts exactly one derivation mode and
// records every mode it was called with.
func unlockOnly(accepted bool, tried *[]bool) func(bool) error {
	return func(tpmKeyOnlyMode bool) error {
		*tried = append(*tried, tpmKeyOnlyMode)
		if tpmKeyOnlyMode == accepted {
			return nil
		}
		return errors.New("key does not unlock this vault")
	}
}

func TestResolveKeyModeStopsOnceTheVaultOpens(t *testing.T) {
	var tried []bool
	mode, err := resolveKeyMode(testLog(), true, unlockOnly(true, &tried))
	assert.NoError(t, err)
	assert.Equal(t, true, mode)
	assert.Equal(t, []bool{true}, tried, "the preferred mode worked; nothing else may be tried")
}

// The case the fallback exists for, in both of its forms: a vault created
// TPM-key-only whose recorded mode names the merged derivation, whether that
// record came from an earlier boot's guess or from a recreate that moved the
// vault out from under it.
func TestResolveKeyModeRecoversFromAWrongPreference(t *testing.T) {
	var tried []bool
	mode, err := resolveKeyMode(testLog(), false, unlockOnly(true, &tried))
	assert.NoError(t, err)
	assert.Equal(t, true, mode, "the mode that opened the vault must be the one reported")
	assert.Equal(t, []bool{false, true}, tried)
}

// The fallback is not conditional on where the preferred mode came from. A
// mode read back from the persisted vault config is only as good as the boot
// that wrote it, so it gets the same second attempt.
func TestResolveKeyModeRetriesARecordedMode(t *testing.T) {
	var tried []bool
	mode, err := resolveKeyMode(testLog(), true, unlockOnly(false, &tried))
	assert.NoError(t, err)
	assert.Equal(t, false, mode)
	assert.Equal(t, []bool{true, false}, tried)
}

func TestResolveKeyModeReportsBothFailures(t *testing.T) {
	var tried []bool
	unlock := func(tpmKeyOnlyMode bool) error {
		tried = append(tried, tpmKeyOnlyMode)
		if tpmKeyOnlyMode {
			return errors.New("tpm-only refused")
		}
		return errors.New("merged refused")
	}
	_, err := resolveKeyMode(testLog(), true, unlock)
	assert.Error(t, err)
	assert.Equal(t, []bool{true, false}, tried)
	// Neither derivation may be blamed on its own: the seal, not the mode, is
	// then the likely cause, and both errors are what says so.
	assert.Contains(t, err.Error(), "tpm-only refused")
	assert.Contains(t, err.Error(), "merged refused")
}

// What the caller persists afterwards has to be the derivation that opened the
// vault, not the one that was tried first.
func TestResolveUnlockRecordsTheModeThatWorked(t *testing.T) {
	var tried []bool
	options := HandlerOptions{TpmKeyOnlyMode: false}
	err := options.resolveUnlock(testLog(), unlockOnly(true, &tried))
	assert.NoError(t, err)
	assert.True(t, options.TpmKeyOnlyMode)
	assert.Equal(t, []bool{false, true}, tried)
}

// Neither derivation worked, so the mode is still unknown. Leaving the options
// as they were is what keeps the caller from persisting one on the strength of
// a failed unlock.
func TestResolveUnlockLeavesAnUnresolvedModeAlone(t *testing.T) {
	var tried []bool
	options := HandlerOptions{TpmKeyOnlyMode: true}
	err := options.resolveUnlock(testLog(), func(tpmKeyOnlyMode bool) error {
		tried = append(tried, tpmKeyOnlyMode)
		return errors.New("key does not unlock this vault")
	})
	assert.Error(t, err)
	assert.Equal(t, HandlerOptions{TpmKeyOnlyMode: true}, options)
	assert.Equal(t, []bool{true, false}, tried)
}
