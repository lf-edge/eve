// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ControllerCert.Key / LogKey

func TestControllerCertLogKey(t *testing.T) {
	hash := []byte{0xde, 0xad, 0xbe, 0xef}
	cert := ControllerCert{CertHash: hash}
	assert.Equal(t, hex.EncodeToString(hash), cert.Key())
	assert.Contains(t, cert.LogKey(), hex.EncodeToString(hash))
}
