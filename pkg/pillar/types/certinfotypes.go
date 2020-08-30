// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"

	"github.com/google/go-cmp/cmp"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ControllerCert : controller certicate
// config received from controller
type ControllerCert struct {
	HashAlgo zcommon.HashAlgorithm
	Type     zcert.ZCertType
	Cert     []byte
	CertHash []byte
}

// Key :
func (cert *ControllerCert) Key() string {
	return hex.EncodeToString(cert.CertHash)
}

// LogCreate :
func (cert ControllerCert) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ControllerCertLogType, "",
		nilUUID, cert.LogKey())
	if logObject == nil {
		return
	}
	logObject.Tracef("Controller cert create")
}

// LogModify :
func (cert ControllerCert) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(nil, base.ControllerCertLogType, "",
		nilUUID, cert.LogKey())

	oldCert, ok := old.(ControllerCert)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ControllerCert type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldCert, cert)).
		Tracef("Controller cert modify")
}

// LogDelete :
func (cert ControllerCert) LogDelete() {
	logObject := base.EnsureLogObject(nil, base.ControllerCertLogType, "",
		nilUUID, cert.LogKey())
	logObject.Tracef("Controller cert delete")

	base.DeleteLogObject(cert.LogKey())
}

// LogKey :
func (cert ControllerCert) LogKey() string {
	return string(base.ControllerCertLogType) + "-" + cert.Key()
}
