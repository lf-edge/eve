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

func TestResolveKeyModeUsesTheKnownModeOnly(t *testing.T) {
	// A mode read back from the persisted vault config is not a guess, so a
	// failure must be reported rather than papered over by trying the other key.
	var tried []bool
	mode, err := resolveKeyMode(testLog(), true, false, unlockOnly(false, &tried))
	assert.Error(t, err)
	assert.Equal(t, true, mode)
	assert.Equal(t, []bool{true}, tried, "a known mode must not be second-guessed")
}

func TestResolveKeyModeKeepsAWorkingKnownMode(t *testing.T) {
	var tried []bool
	mode, err := resolveKeyMode(testLog(), true, false, unlockOnly(true, &tried))
	assert.NoError(t, err)
	assert.Equal(t, true, mode)
	assert.Equal(t, []bool{true}, tried)
}

func TestResolveKeyModeTriesInferredModeFirst(t *testing.T) {
	var tried []bool
	mode, err := resolveKeyMode(testLog(), false, true, unlockOnly(false, &tried))
	assert.NoError(t, err)
	assert.Equal(t, false, mode)
	assert.Equal(t, []bool{false}, tried, "the inferred mode worked; nothing else may be tried")
}

// The case this exists for: the vault was created TPM-key-only but the persisted
// config was lost, so the inferred mode names the merged derivation.
func TestResolveKeyModeRecoversFromAWrongInference(t *testing.T) {
	var tried []bool
	mode, err := resolveKeyMode(testLog(), false, true, unlockOnly(true, &tried))
	assert.NoError(t, err)
	assert.Equal(t, true, mode, "the mode that opened the vault must be the one reported")
	assert.Equal(t, []bool{false, true}, tried)
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
	_, err := resolveKeyMode(testLog(), true, true, unlock)
	assert.Error(t, err)
	assert.Equal(t, []bool{true, false}, tried)
	// Neither derivation may be blamed on its own: the seal, not the mode, is
	// then the likely cause, and both errors are what says so.
	assert.Contains(t, err.Error(), "tpm-only refused")
	assert.Contains(t, err.Error(), "merged refused")
}
