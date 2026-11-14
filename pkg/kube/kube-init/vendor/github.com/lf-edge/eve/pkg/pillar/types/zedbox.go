// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ServiceInitStatus used to track/notify service init in zedbox
type ServiceInitStatus struct {
	ServiceName string
	CmdArgs     []string
}

// Key returns the pubsub Key
func (s ServiceInitStatus) Key() string {
	return s.ServiceName
}

// LogCreate :
func (s ServiceInitStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.ServiceInitLogType, s.ServiceName, nilUUID, s.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("servicename", s.ServiceName).
		AddField("cmdargs", s.CmdArgs).
		Noticef("ServiceInitStatus create")
}

// LogModify :
func (s ServiceInitStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.ServiceInitLogType, s.ServiceName, nilUUID, s.LogKey())

	if _, ok := old.(ServiceInitStatus); !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of ServiceInitStatus type")
	}

	logObject.CloneAndAddField("servicename", s.ServiceName).
		AddField("cmdargs", s.CmdArgs).
		Noticef("ServiceInitStatus modify")
}

// LogDelete :
func (s ServiceInitStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.ServiceInitLogType, s.ServiceName, nilUUID, s.LogKey())
	logObject.CloneAndAddField("servicename", s.ServiceName).
		AddField("cmdargs", s.CmdArgs).
		Noticef("ServiceInitStatus modify")

	base.DeleteLogObject(logBase, s.LogKey())
}

// LogKey :
func (s ServiceInitStatus) LogKey() string {
	return string(base.ServiceInitLogType) + "-" + s.Key()
}
