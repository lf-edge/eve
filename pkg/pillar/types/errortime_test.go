// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"reflect"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
