// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// CipherContext.Key / ControllerCertKey / EdgeNodeCertKey / LogKey

func TestCipherContextLogKey(t *testing.T) {
	ctrlHash := []byte{0x01, 0x02}
	devHash := []byte{0x03, 0x04}
	ctx := CipherContext{
		ContextID:          "ctx-123",
		ControllerCertHash: ctrlHash,
		DeviceCertHash:     devHash,
	}
	assert.Equal(t, "ctx-123", ctx.Key())
	assert.Equal(t, hex.EncodeToString(ctrlHash), ctx.ControllerCertKey())
	assert.Equal(t, hex.EncodeToString(devHash), ctx.EdgeNodeCertKey())
	assert.Contains(t, ctx.LogKey(), "ctx-123")
}

// CipherBlockStatus.Key / LogKey

func TestCipherBlockStatusLogKey(t *testing.T) {
	status := CipherBlockStatus{CipherBlockID: "block-abc"}
	assert.Equal(t, "block-abc", status.Key())
	assert.Contains(t, status.LogKey(), "block-abc")
}
