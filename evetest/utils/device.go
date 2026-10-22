// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/rand"
	"fmt"
)

const serialAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomDeviceSerial returns a random alphanumeric device serial number.
// The serial contains only letters and digits (no special characters)
// and is suitable for use as a device identifier.
func RandomDeviceSerial(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid serial length %d", length)
	}

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := range b {
		b[i] = serialAlphabet[int(b[i])%len(serialAlphabet)]
	}
	return string(b), nil
}
