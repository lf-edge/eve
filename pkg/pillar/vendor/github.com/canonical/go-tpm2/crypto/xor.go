// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypto

import (
	"crypto"

	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
)

// XORObfuscation performs XOR obfuscation as described in part 1 of the TPM
// library specification.
//
// This will panic if hashAlg is not available.
//
// Deprecated:
func XORObfuscation(hashAlg crypto.Hash, key []byte, contextU, contextV, data []byte) {
	internal_crypt.XORObfuscation(hashAlg, key, contextU, contextV, data)
}
