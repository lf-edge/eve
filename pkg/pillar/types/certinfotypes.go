// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	zcert "github.com/lf-edge/eve/api/go/certs"
	"time"
)

// ControllerCertConfig : controller certicate
// config received from controller
type ControllerCertConfig struct {
	HashAlgo zcert.CertHashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	CertHash []byte
}

// Key :
func (cert *ControllerCertConfig) Key() string {
	return hex.EncodeToString(cert.CertHash)
}

// ControllerCertStatus : controller certicate
// status
type ControllerCertStatus struct {
	HashAlgo zcert.CertHashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	CertHash []byte
	ErrorInfo
}

// Key :
func (cert *ControllerCertStatus) Key() string {
	return hex.EncodeToString(cert.CertHash)
}

// SetErrorInfo : sets errorinfo on the controller cert
func (cert *ControllerCertStatus) SetErrorInfo(agentName, errStr string) {
	cert.Error = errStr
	cert.ErrorTime = time.Now()
	cert.ErrorSource = agentName
}

// ClearErrorInfo : clears errorinfo on the controller cert
func (cert *ControllerCertStatus) ClearErrorInfo() {
	cert.Error = ""
	cert.ErrorSource = ""
	cert.ErrorTime = time.Time{}
}
