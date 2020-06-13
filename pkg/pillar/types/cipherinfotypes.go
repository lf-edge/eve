// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	zconfig "github.com/lf-edge/eve/api/go/config"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
)

// EncryptionBlock - This is a Mirror of
// api/proto/config/acipherinfo.proto - EncryptionBlock
// Always need to keep these two consistent.
type EncryptionBlock struct {
	DsAPIKey          string
	DsPassword        string
	WifiUserName      string // If the authentication type is EAP
	WifiPassword      string
	ProtectedUserData string
}

// CipherContextConfig : a pair of device and controller certificate
// published by controller along with some attributes // part of EdgeDevConfig block, received from controller
type CipherContextConfig struct {
	ContextID          string
	HashScheme         zcommon.HashAlgorithm
	KeyExchangeScheme  zconfig.KeyExchangeScheme
	EncryptionScheme   zconfig.EncryptionScheme
	ControllerCertHash []byte
	DeviceCertHash     []byte
}

// Key :
func (config *CipherContextConfig) Key() string {
	return config.ContextID
}

// ControllerCertKey :
func (config *CipherContextConfig) ControllerCertKey() string {
	return hex.EncodeToString(config.ControllerCertHash)
}

// EveNodeCertKey :
func (config *CipherContextConfig) EveNodeCertKey() string {
	return hex.EncodeToString(config.DeviceCertHash)
}

// CipherContextStatus : context information for the pair
// of certificates
type CipherContextStatus struct {
	CipherContextConfig
	ControllerCert []byte // resolved through CERT API
	ErrorAndTime
}

// Key :
func (status *CipherContextStatus) Key() string {
	return status.ContextID
}

// ControllerCertKey :
func (status *CipherContextStatus) ControllerCertKey() string {
	return hex.EncodeToString(status.ControllerCertHash)
}

// EveNodeCertKey :
func (status *CipherContextStatus) EveNodeCertKey() string {
	return hex.EncodeToString(status.DeviceCertHash)
}

// CipherBlockStatus : Object specific encryption information
type CipherBlockStatus struct {
	CipherBlockID     string // constructed using individual reference
	CipherContextID   string // cipher context id
	HashScheme        zcommon.HashAlgorithm
	KeyExchangeScheme zconfig.KeyExchangeScheme
	EncryptionScheme  zconfig.EncryptionScheme
	InitialValue      []byte
	CipherData        []byte
	ClearTextHash     []byte
	IsCipher          bool
	ErrorAndTime
}

// Key :
func (status *CipherBlockStatus) Key() string {
	return status.CipherBlockID
}
