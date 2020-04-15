// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	zcert "github.com/lf-edge/eve/api/go/certs"
	"time"
)

// ControllerCert : controller certicate
// config received from controller
type ControllerCert struct {
	HashAlgo zcert.CertHashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	CertHash []byte
	ErrorInfo
}

// Key :
func (cert *ControllerCert) Key() string {
	return hex.EncodeToString(cert.CertHash)
}

// SetErrorInfo : sets errorinfo on the controller cert
func (cert *ControllerCert) SetErrorInfo(agentName, errStr string) {
	cert.Error = errStr
	cert.ErrorTime = time.Now()
	cert.ErrorSource = agentName
}

// ClearErrorInfo : clears errorinfo on the controller cert
func (cert *ControllerCert) ClearErrorInfo() {
	cert.Error = ""
	cert.ErrorSource = ""
	cert.ErrorTime = time.Time{}
}
