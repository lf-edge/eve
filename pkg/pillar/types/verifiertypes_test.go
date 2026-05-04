// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// VerifyImageConfig.Key / LogKey

func TestVerifyImageConfigLogKey(t *testing.T) {
	cfg := VerifyImageConfig{ImageSha256: "abc123"}
	assert.Equal(t, "abc123", cfg.Key())
	assert.Contains(t, cfg.LogKey(), "abc123")
}

// VerifyImageStatus.Key / LogKey

func TestVerifyImageStatusLogKey(t *testing.T) {
	status := VerifyImageStatus{ImageSha256: "def456"}
	assert.Equal(t, "def456", status.Key())
	assert.Contains(t, status.LogKey(), "def456")
}
