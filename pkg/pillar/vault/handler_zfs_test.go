// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFstrimBinaryExists verifies that fstrim is present on PATH. TrimVault
// depends on it; a missing binary would silently fail at runtime on first boot.
func TestFstrimBinaryExists(t *testing.T) {
	_, err := exec.LookPath("fstrim")
	assert.NoError(t, err, "fstrim must be present on PATH; TrimVault will fail without it")
}
