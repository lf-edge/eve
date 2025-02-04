// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package crypt

import (
	"crypto/cipher"
	"fmt"
)

type SymmetricAlgorithm interface {
	NewCipher(key []byte) (cipher.Block, error)
}

// SymmetricEncrypt performs in place symmetric encryption of the supplied
// data with the supplied cipher using CFB mode.
func SymmetricEncrypt(alg SymmetricAlgorithm, key, iv, data []byte) error {
	c, err := alg.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot create cipher: %w", err)
	}
	// The TPM uses CFB cipher mode for all secret sharing
	s := cipher.NewCFBEncrypter(c, iv)
	s.XORKeyStream(data, data)
	return nil
}

// SymmetricDecrypt performs in place symmetric decryption of the supplied
// data with the supplied cipher using CFB mode.
func SymmetricDecrypt(alg SymmetricAlgorithm, key, iv, data []byte) error {
	c, err := alg.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cannot create cipher: %w", err)
	}
	// The TPM uses CFB cipher mode for all secret sharing
	s := cipher.NewCFBDecrypter(c, iv)
	s.XORKeyStream(data, data)
	return nil
}
