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
