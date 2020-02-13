// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/base64"
	//zcert "github.com/lf-edge/eve/api/go/certs"
)

// ControllerCertificate : controller certicate
type ControllerCertificate struct {
	//	HashAlgo zcert.ZCertHashAlgorithm
	//	Type     zcert.ZCertType
	//	Attr     zcert.ZCertProperties
	Cert     []byte
	CertHash []byte
}

// Key :
func (cert *ControllerCertificate) Key() string {
	return base64.StdEncoding.EncodeToString(cert.CertHash)
}
