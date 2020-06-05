// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	zcert "github.com/lf-edge/eve/api/go/certs"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
)

// ControllerCertConfig : controller certicate
// config received from controller
type ControllerCertConfig struct {
	HashAlgo zcommon.HashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	Hash     []byte
}

// Key :
func (cert *ControllerCertConfig) Key() string {
	return hex.EncodeToString(cert.Hash)
}

// ControllerCertStatus : controller certicate
// status
type ControllerCertStatus struct {
	HashAlgo zcommon.HashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	Hash     []byte
	ErrorAndTime
}

// Key :
func (cert *ControllerCertStatus) Key() string {
	return hex.EncodeToString(cert.Hash)
}

// EveNodeCertConfig : controller certicate
// config received from controller
type EveNodeCertConfig struct {
	HashAlgo zcommon.HashAlgorithm
	Type     zcommon.ZCertType
	Hash     []byte
	Cert     []byte
	PvtKey   []byte
}

// Key :
func (cert *EveNodeCertConfig) Key() string {
	return hex.EncodeToString(cert.Hash)
}

// EveNodeCertStatus : controller certicate
// status
type EveNodeCertStatus struct {
	HashAlgo zcommon.HashAlgorithm
	Type     zcommon.ZCertType
	Hash     []byte
	Cert     []byte
	ErrorAndTime
}

// Key :
func (cert *EveNodeCertStatus) Key() string {
	return hex.EncodeToString(cert.Hash)
}
