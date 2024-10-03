// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// OnboardingStatus - UUID, etc. advertised by client process
type OnboardingStatus struct {
	DeviceUUID    uuid.UUID
	HardwareModel string // From controller
}

// Key returns the key for pubsub
func (status OnboardingStatus) Key() string {
	return "global"
}

// LogCreate :
func (status OnboardingStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.OnboardingStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Onboarding status create")
}

// LogModify :
func (status OnboardingStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.OnboardingStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(OnboardingStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of OnboardingStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Onboarding status modify")
}

// LogDelete :
func (status OnboardingStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.OnboardingStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.Noticef("Onboarding status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status OnboardingStatus) LogKey() string {
	return string(base.OnboardingStatusLogType) + "-" + status.Key()
}
