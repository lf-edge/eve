// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
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

// EdgeNodeCertKey :
func (status *CipherContext) EdgeNodeCertKey() string {
	return hex.EncodeToString(status.DeviceCertHash)
}

// LogCreate :
func (status CipherContext) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.CipherContextLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Cipher block status create")
}

// LogModify :
func (status CipherContext) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.CipherContextLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(CipherContext)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of CipherContext type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Cipher block status modify")
}

// LogDelete :
func (status CipherContext) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.CipherContextLogType, "",
		nilUUID, status.LogKey())
	logObject.Noticef("Cipher block status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status CipherContext) LogKey() string {
	return string(base.CipherContextLogType) + "-" + status.Key()
}

// CipherBlockStatus : Object specific encryption information
type CipherBlockStatus struct {
	CipherBlockID   string // constructed using individual reference
	CipherContextID string // cipher context id
	InitialValue    []byte
	CipherData      []byte `json:"pubsub-large-CipherData"`
	ClearTextHash   []byte
	IsCipher        bool
	CipherContext   *CipherContext
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// Key :
func (status *CipherBlockStatus) Key() string {
	return status.CipherBlockID
}

// LogCreate :
func (status CipherBlockStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.CipherBlockStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Cipher block status create")
}

// LogModify :
func (status CipherBlockStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.CipherBlockStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(CipherBlockStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of CipherBlockStatus type")
	}
	// XXX remove? XXX huge?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Cipher block status modify")
}

// LogDelete :
func (status CipherBlockStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.CipherBlockStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.Noticef("Cipher block status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status CipherBlockStatus) LogKey() string {
	return string(base.CipherBlockStatusLogType) + "-" + status.Key()
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
