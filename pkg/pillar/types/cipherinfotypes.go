// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	zconfig "github.com/lf-edge/eve/api/go/config"
	"time"
)

// CipherContextConfig : a pair of device and controller certificate
// published by controller along with some attributes
// part of EdgeDevConfig block, received from controller
type CipherContextConfig struct {
	ContextID          string
	HashScheme         zconfig.CipherHashAlgorithm
	KeyExchangeScheme  zconfig.KeyExchangeScheme
	EncryptionScheme   zconfig.EncryptionScheme
	ControllerCertHash []byte
	DeviceCertHash     []byte
}

// Key :
func (config *CipherContextConfig) Key() string {
	return config.ContextID
}

// CipherContextStatus : context information for the pair
// of certificates
type CipherContextStatus struct {
	ContextID          string
	HashScheme         zconfig.CipherHashAlgorithm
	KeyExchangeScheme  zconfig.KeyExchangeScheme
	EncryptionScheme   zconfig.EncryptionScheme
	ControllerCertHash []byte
	DeviceCertHash     []byte
	ControllerCert     []byte // resolved through cert API
	DeviceCert         []byte // local device certificate
	ErrorInfo
}

// Key :
func (status *CipherContextStatus) Key() string {
	return status.ContextID
}

// SetErrorInfo : sets errorinfo on the cipher context status object
func (status *CipherContextStatus) SetErrorInfo(agentName, strErr string) {
	status.Error = strErr
	status.ErrorTime = time.Now()
	status.ErrorSource = agentName
}

// ClearErrorInfo : clears errorinfo on the cipher context status object
func (status *CipherContextStatus) ClearErrorInfo() {
	status.Error = ""
	status.ErrorSource = ""
	status.ErrorTime = time.Time{}
}

// CipherBlockStatus : Object specific encryption information
type CipherBlockStatus struct {
	CipherBlockID     string                    // constructed using individual reference
	CipherContextID   string                    // cipher context id
	KeyExchangeScheme zconfig.KeyExchangeScheme // from cipher context
	EncryptionScheme  zconfig.EncryptionScheme  // from cipher context
	ControllerCert    []byte                    // inherited from cipher context
	DeviceCert        []byte                    // inherited from cipher context
	InitialValue      []byte
	CipherData        []byte
	ClearTextHash     []byte
	IsCipher          bool
	ErrorInfo
}

// Key :
func (status *CipherBlockStatus) Key() string {
	return status.CipherBlockID
}

// SetErrorInfo : sets errorinfo on the cipher block status object
func (status *CipherBlockStatus) SetErrorInfo(agentName, errStr string) {
	status.Error = errStr
	status.ErrorTime = time.Now()
	status.ErrorSource = agentName
}

// ClearErrorInfo : clears errorinfo on the cipher block status object
func (status *CipherBlockStatus) ClearErrorInfo() {
	status.Error = ""
	status.ErrorSource = ""
	status.ErrorTime = time.Time{}
}
