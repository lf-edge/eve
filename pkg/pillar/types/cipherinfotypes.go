// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	zconfig "github.com/lf-edge/eve/api/go/config"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
)

// CipherContext : a pair of device and controller certificate
// published by controller along with some attributes
// part of EdgeDevConfig block, received from controller
type CipherContext struct {
	ContextID          string
	HashScheme         zcommon.HashAlgorithm
	KeyExchangeScheme  zconfig.KeyExchangeScheme
	EncryptionScheme   zconfig.EncryptionScheme
	ControllerCertHash []byte
	DeviceCertHash     []byte
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (status *CipherContext) Key() string {
	return status.ContextID
}

// ControllerCertKey :
func (status *CipherContext) ControllerCertKey() string {
	return hex.EncodeToString(status.ControllerCertHash)
}

// CipherBlockStatus : Object specific encryption information
type CipherBlockStatus struct {
	CipherBlockID   string // constructed using individual reference
	CipherContextID string // cipher context id
	InitialValue    []byte
	CipherData      []byte
	ClearTextHash   []byte
	IsCipher        bool
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (status *CipherBlockStatus) Key() string {
	return status.CipherBlockID
}

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
