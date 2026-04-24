// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"reflect"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type simple struct {
	ErrorAndTimeWithSource
}

func TestIsErrorSource(t *testing.T) {
	status := simple{}
	errStr := "test1"
	status.SetErrorWithSource(errStr, ContentTreeStatus{}, time.Now())
	logrus.Infof("set error %s", status.Error)
	assert.True(t, status.HasError())
	assert.True(t, status.IsErrorSource(ContentTreeStatus{}))
	assert.False(t, status.IsErrorSource(VolumeStatus{}))
	assert.Equal(t, errStr, status.Error)

	status.ClearErrorWithSource()
	logrus.Infof("cleared error %s", status.Error)
	assert.False(t, status.IsErrorSource(ContentTreeStatus{}))
	assert.Equal(t, "", status.Error)

	errStr = "error2"
	status.SetError(errStr, time.Now())
	assert.Equal(t, errStr, status.Error)
	logrus.Infof("type after SetError %s %T", status.ErrorSourceType, status.ErrorSourceType)
	logrus.Infof("reflect %v", reflect.TypeOf(status.ErrorSourceType))

	errStr = "error3"
	status.SetErrorWithSource(errStr, ContentTreeStatus{}, time.Now())
	logrus.Infof("type after SetErrorWithSource %s %T", status.ErrorSourceType, status.ErrorSourceType)
	logrus.Infof("reflect %v", reflect.TypeOf(status.ErrorSourceType))

	errStr = "error4"
	status.SetError(errStr, time.Now())
	assert.Equal(t, errStr, status.Error)
	logrus.Infof("type after SetError %s %T", status.ErrorSourceType, status.ErrorSourceType)
	logrus.Infof("reflect %v", reflect.TypeOf(status.ErrorSourceType))

	errStr = "error5"
	// XXX now fatals
	// result := make(map[string]interface{})
	// status.SetErrorWithSource(errStr, result, time.Now())
	logrus.Infof("type after SetError %s %T", status.ErrorSourceType, status.ErrorSourceType)
	logrus.Infof("reflect %v", reflect.TypeOf(status.ErrorSourceType))
}

// ErrorAndTime.SetErrorNow

func TestErrorAndTimeSetErrorNow(t *testing.T) {
	var et ErrorAndTime
	before := time.Now()
	et.SetErrorNow("something went wrong")
	after := time.Now()

	assert.Equal(t, "something went wrong", et.Error)
	assert.True(t, et.HasError())
	assert.True(t, !et.ErrorTime.Before(before))
	assert.True(t, !et.ErrorTime.After(after))
}

// GetErrorSeverity

func TestGetErrorSeverityBoundaries(t *testing.T) {
	// Below both warning thresholds → Notice
	assert.Equal(t, ErrorSeverityNotice,
		GetErrorSeverity(0, 0))
	assert.Equal(t, ErrorSeverityNotice,
		GetErrorSeverity(RetryCountWarning, RetryTimeWarning))

	// Just over count warning threshold
	assert.Equal(t, ErrorSeverityWarning,
		GetErrorSeverity(RetryCountWarning+1, 0))

	// Just over time warning threshold
	assert.Equal(t, ErrorSeverityWarning,
		GetErrorSeverity(0, RetryTimeWarning+1))

	// Over count error threshold
	assert.Equal(t, ErrorSeverityError,
		GetErrorSeverity(RetryCountError+1, 0))

	// Over time error threshold
	assert.Equal(t, ErrorSeverityError,
		GetErrorSeverity(0, RetryTimeError+1))
}

// ErrorAndTime.ClearError

func TestErrorAndTimeClearError(t *testing.T) {
	et := ErrorAndTime{}
	et.SetErrorNow("some error")
	assert.True(t, et.HasError())

	et.ClearError()
	assert.False(t, et.HasError())
	assert.Equal(t, "", et.Error)
	assert.True(t, et.ErrorTime.IsZero())
	assert.Equal(t, "", et.ErrorRetryCondition)
	assert.Equal(t, ErrorSeverityUnspecified, et.ErrorSeverity)
}

// ErrorAndTimeWithSource.SetErrorWithSourceAndDescription

func TestSetErrorWithSourceAndDescription(t *testing.T) {
	et := ErrorAndTimeWithSource{}
	desc := ErrorDescription{
		Error:         "enrollment error",
		ErrorSeverity: ErrorSeverityWarning,
	}
	et.SetErrorWithSourceAndDescription(desc, ContentTreeStatus{})
	assert.True(t, et.HasError())
	assert.Equal(t, "enrollment error", et.Error)
	assert.Equal(t, ErrorSeverityWarning, et.ErrorSeverity)
	assert.True(t, et.IsErrorSource(ContentTreeStatus{}))
}

// ErrorDescription.ToProto

func TestErrorDescriptionToProto(t *testing.T) {
	// Zero ErrorTime → nil
	ed := ErrorDescription{}
	assert.Nil(t, ed.ToProto())

	// Non-zero ErrorTime → populated ErrorInfo
	now := time.Now()
	ed = ErrorDescription{
		Error:               "disk full",
		ErrorSeverity:       ErrorSeverityError,
		ErrorRetryCondition: "retry in 5m",
		ErrorEntities: []*ErrorEntity{
			{EntityID: "vol-1", EntityType: ErrorEntityAppInstance},
		},
	}
	ed.ErrorTime = now

	got := ed.ToProto()
	require.NotNil(t, got)
	assert.Equal(t, "disk full", got.Description)
	assert.Equal(t, info.Severity(ErrorSeverityError), got.Severity)
	assert.Equal(t, "retry in 5m", got.RetryCondition)
	require.Len(t, got.Entities, 1)
	assert.Equal(t, "vol-1", got.Entities[0].EntityId)
}

// ErrorAndTimeWithSource.SetErrorWithSource — string source branch

func TestSetErrorWithSourceStringSource(t *testing.T) {
	et := ErrorAndTimeWithSource{}
	now := time.Now()
	et.SetErrorWithSource("some error", "myModule", now)
	assert.True(t, et.HasError())
	assert.Equal(t, "some error", et.Error)
	assert.Equal(t, "myModule", et.ErrorSourceType)
}

// ErrorAndTimeWithSource.SetErrorWithSourceAndDescription — string source branch

func TestSetErrorWithSourceAndDescriptionStringSource(t *testing.T) {
	et := ErrorAndTimeWithSource{}
	desc := ErrorDescription{
		Error:         "module error",
		ErrorSeverity: ErrorSeverityWarning,
	}
	et.SetErrorWithSourceAndDescription(desc, "myStringSource")
	assert.True(t, et.HasError())
	assert.Equal(t, "module error", et.Error)
	assert.Equal(t, "myStringSource", et.ErrorSourceType)
}

// allowedSourceType — map branch

func TestAllowedSourceType(t *testing.T) {
	// String → allowed (true)
	assert.True(t, allowedSourceType("hello"))

	// Map → not allowed (false)
	assert.False(t, allowedSourceType(map[string]interface{}{}))

	// Pointer → not allowed (false)
	x := 42
	assert.False(t, allowedSourceType(&x))

	// Struct → allowed (true)
	assert.True(t, allowedSourceType(ContentTreeStatus{}))
}

// EvalStatus.ElapsedTime — zero and non-zero branches

func TestEvalStatusElapsedTime(t *testing.T) {
	// Zero TestStartTime → returns 0
	s := EvalStatus{}
	assert.Equal(t, time.Duration(0), s.ElapsedTime())

	// Non-zero TestStartTime → returns positive duration
	s = EvalStatus{TestStartTime: time.Now().Add(-5 * time.Second)}
	elapsed := s.ElapsedTime()
	assert.Greater(t, elapsed, time.Duration(0))
	assert.GreaterOrEqual(t, elapsed, 4*time.Second)
}

// EvalStatus.DetailedNote — inventory branch

func TestEvalStatusDetailedNoteInventory(t *testing.T) {
	s := EvalStatus{
		Note:               "test result",
		InventoryCollected: true,
		InventoryDir:       "/tmp/inventory",
	}
	note := s.DetailedNote()
	assert.Contains(t, note, "test result")
	assert.Contains(t, note, "inventory=/tmp/inventory")
}

// EvalStatus.OnboardingBlockReason — multiple branches

func TestEvalStatusOnboardingBlockReasonBranches(t *testing.T) {
	// Not evaluation platform → always ""
	s := EvalStatus{IsEvaluationPlatform: false}
	assert.Equal(t, "", s.OnboardingBlockReason())

	// Evaluation platform, onboarding allowed → ""
	s = EvalStatus{
		IsEvaluationPlatform: true,
		AllowOnboard:         true,
		Phase:                EvalPhaseFinal,
	}
	assert.Equal(t, "", s.OnboardingBlockReason())

	// AllowOnboard=false, Phase=Init
	s = EvalStatus{IsEvaluationPlatform: true, AllowOnboard: false, Phase: EvalPhaseInit}
	assert.Equal(t, "evaluation platform initializing", s.OnboardingBlockReason())

	// AllowOnboard=false, Phase=Testing
	s.Phase = EvalPhaseTesting
	assert.Equal(t, "evaluation platform testing in progress", s.OnboardingBlockReason())

	// AllowOnboard=false, Phase=Final
	s.Phase = EvalPhaseFinal
	assert.Equal(t, "evaluation complete but onboarding explicitly disabled", s.OnboardingBlockReason())

	// AllowOnboard=true, unknown phase → IsOnboardingAllowed()=false, hits phase-based default
	s = EvalStatus{IsEvaluationPlatform: true, AllowOnboard: true, Phase: EvalPhase("unknown")}
	assert.Equal(t, "evaluation platform in unknown state", s.OnboardingBlockReason())
}
