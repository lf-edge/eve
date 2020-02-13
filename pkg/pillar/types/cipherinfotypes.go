// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	zconfig "github.com/lf-edge/eve/api/go/config"
)

// CipherContext : Contains the decryption information
// supplied by controller, for sensitive encrypted data
type CipherContext struct {
	ID                 string
	HashScheme         zconfig.CipherHashAlgorithm
	KeyExchangeScheme  zconfig.KeyExchangeScheme
	EncryptionScheme   zconfig.EncryptionScheme
	ControllerCertHash []byte
	DeviceCertHash     []byte
}

// Key :
func (cipherContext *CipherContext) Key() string {
	return cipherContext.ID
}

// CipherBlock : Object specific encryption information
type CipherBlock struct {
	ID                string
	KeyExchangeScheme zconfig.KeyExchangeScheme
	EncryptionScheme  zconfig.EncryptionScheme
	InitialValue      []byte
	ControllerCert    []byte
	DeviceCert        []byte
	CipherData        []byte
	ClearTextHash     []byte
	IsCipher          bool
	IsValidCipher     bool
}

// Key :
func (cipherBlock *CipherBlock) Key() string {
	return cipherBlock.ID
}

// CredentialBlock : Credential Information
type CredentialBlock struct {
	Identity string
	Password string
}
