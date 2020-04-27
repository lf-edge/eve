// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	zcert "github.com/lf-edge/eve/api/go/certs"
	zcommon "github.com/lf-edge/eve/api/go/common"
)

// ControllerCert : controller certicate
// config received from controller
type ControllerCert struct {
	HashAlgo zcommon.HashAlgorithm
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
