// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypt

import (
	"crypto"
)

// XORObfuscation performs XOR obfuscation as described in part 1 of the TPM
// library specification.
//
// This will panic if hashAlg is not available.
func XORObfuscation(hashAlg crypto.Hash, key []byte, contextU, contextV, data []byte) {
	dataSize := len(data)
	mask := KDFa(hashAlg, key, []byte("XOR"), contextU, contextV, dataSize*8)
	for i := 0; i < dataSize; i++ {
		data[i] ^= mask[i]
	}
}
