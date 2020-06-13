// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/api/go/evecommon"
)

type ZCertOrigin uint8

const (
	CERT_ORIGIN_NONE ZCertOrigin = iota + 0
	CERT_ORIGIN_CONTROLLER
	CERT_ORIGIN_EVE_NODE_SOFTWARE
	CERT_ORIGIN_EVE_NODE_TPM
	CERT_ORIGIN_EVE_NODE_HSM
)

// ZCertConfig : basic certificate config structure
type ZCertConfig struct {
	HashAlgo  evecommon.HashAlgorithm
	Type      evecommon.ZCertType
	Origin    ZCertOrigin
	TpmHandle tpmutil.Handle
	Hash      []byte
	Cert      []byte
	PvtKey    []byte
}

// Key :
func (cert *ZCertConfig) Key() string {
	return hex.EncodeToString(cert.Hash)
}

// ZCertStatus : basic certificate structure
type ZCertStatus struct {
	ZCertConfig
	ErrorAndTime
}

// Key :
func (cert *ZCertStatus) Key() string {
	return hex.EncodeToString(cert.Hash)
}
