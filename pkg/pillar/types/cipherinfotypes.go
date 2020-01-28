// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	zconfig "github.com/lf-edge/eve/api/go/config"
)

// CipherInfo : Contains the decryption information
// supplied by controller, for sensitive encrypted data
type CipherInfo struct {
	ID                         string
	KeyExchangeScheme          zconfig.KeyExchangeScheme
	EncryptionScheme           zconfig.EncryptionScheme
	InitialValue               []byte
	ControllerCert             []byte
	ControllerCertSha256       string
	DeviceCertSha256           string
	ControllerCertShaSignature []byte
}

// Key :
func (cipherInfo *CipherInfo) Key() string {
	return cipherInfo.Id
}
