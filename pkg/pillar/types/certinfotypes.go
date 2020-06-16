// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	"github.com/google/go-tpm/tpmutil"
)

// hashing algorithm used for a payload
type ZHashAlgorithm uint8

const (
	HASH_ALGORITHM_NONE ZHashAlgorithm = iota + 0
	HASH_ALGORITHM_SH256_16BYTES
	HASH_ALGORITHM_SH256_32BYTES
)

// various certificate types
type ZCertType uint8

const (
	CERT_TYPE_NONE ZCertType = iota + 0
	CERT_TYPE_CONTROLLER_SIGNING
	CERT_TYPE_CONTROLLER_INTERMEDIATE
	CERT_TYPE_CONTROLLER_ECDH_EXCHANGE
	CERT_TYPE_DEVICE_ONBOARDING
	CERT_TYPE_DEVICE_RESTRICTED_SIGNING
	CERT_TYPE_DEVICE_ENDORSEMENT_RSA
	CERT_TYPE_DEVICE_ECDH_EXCHANGE
)

// denotes source of device certificate
type ZCertOrigin uint8

const (
	CERT_ORIGIN_NONE ZCertOrigin = iota + 0
	CERT_ORIGIN_DEVICE_SOFTWARE
	CERT_ORIGIN_DEVICE_TPM
)

// ControllerCert : controller certificate
// config received from controller
type ControllerCert struct {
	HashAlgo ZHashAlgorithm
	Type     ZCertType
	Cert     []byte
	CertHash []byte
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (cert *ControllerCert) Key() string {
	return hex.EncodeToString(cert.CertHash)
}

// DeviceCert : device certificate
// device generated certificate
type DeviceCert struct {
	HashAlgo  ZHashAlgorithm
	Type      ZCertType
	Cert      []byte
	CertHash  []byte
	Origin    ZCertOrigin
	PvtKey    []byte
	TpmHandle tpmutil.Handle
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (cert *DeviceCert) Key() string {
	return hex.EncodeToString(cert.CertHash)
}
