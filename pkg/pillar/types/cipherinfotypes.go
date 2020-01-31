// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	zconfig "github.com/lf-edge/eve/api/go/config"
)

// CipherContain : Decryption information
// supplied by controller, for sensitive encrypted data
type CipherContext struct {
	ID                   UUIDandVersion
	KeyExchangeScheme    zconfig.KeyExchangeScheme
	EncryptionScheme     zconfig.EncryptionScheme
	ControllerCert       []byte
	ControllerCertSha256 string
	DeviceCertSha256     string
}

// Key :
func (cipherContext *CipherContext) Key() string {
	return cipherContext.ID.UUID.String()
}

// CipherBlock : Encrypted Information
type CipherBlock struct {
	ID                   string
	KeyExchangeScheme    zconfig.KeyExchangeScheme
	EncryptionScheme     zconfig.EncryptionScheme
	InitialValue         []byte
	ControllerCert       []byte
	ControllerCertSha256 string
	DeviceCertSha256     string
	CipherData           []byte
	DataSha256           string
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
