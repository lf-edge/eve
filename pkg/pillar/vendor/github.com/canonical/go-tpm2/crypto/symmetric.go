// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypto

import (
	"crypto/cipher"

	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
)

type SymmetricAlgorithm interface {
	NewCipher(key []byte) (cipher.Block, error)
}

// SymmetricEncrypt performs in place symmetric encryption of the supplied
// data with the supplied cipher using CFB mode.
//
// Deprecated: Use [cipher.Block] and [cipher.Stream] directly.
func SymmetricEncrypt(alg SymmetricAlgorithm, key, iv, data []byte) error {
	return internal_crypt.SymmetricEncrypt(alg, key, iv, data)
}

// SymmetricDecrypt performs in place symmetric decryption of the supplied
// data with the supplied cipher using CFB mode.
//
// Deprecated: Use [cipher.Block] and [cipher.Stream] directly.
func SymmetricDecrypt(alg SymmetricAlgorithm, key, iv, data []byte) error {
	return internal_crypt.SymmetricDecrypt(alg, key, iv, data)
}
