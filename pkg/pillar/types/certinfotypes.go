// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	zcert "github.com/lf-edge/eve/api/go/certs"
)

// ControllerCert : controller certicate
// config received from controller
type ControllerCert struct {
	HashAlgo zcert.CertHashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	CertHash []byte
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (cert *ControllerCert) Key() string {
	return hex.EncodeToString(cert.CertHash)
}
