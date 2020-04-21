// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
)

// Common error with timestamp

// ErrorAndTime is used by many EVE agents
type ErrorAndTime struct {
	Error     string
	ErrorTime time.Time
}

// SetErrorNow uses the current time
func (etPtr *ErrorAndTime) SetErrorNow(errStr string) {
	if errStr == "" {
		log.Fatal("Missing error string")
	}
	etPtr.Error = errStr
	etPtr.ErrorTime = time.Now()
}

// SetError is when time is specified
func (etPtr *ErrorAndTime) SetError(errStr string, errorTime time.Time) {
	if errStr == "" {
		log.Fatal("Missing error string")
	}
	etPtr.Error = errStr
	etPtr.ErrorTime = errorTime
}

// ClearError removes it
func (etPtr *ErrorAndTime) ClearError() {
	etPtr.Error = ""
	etPtr.ErrorTime = time.Time{}
}

// HasError returns true if there is an error
func (etPtr *ErrorAndTime) HasError() bool {
	return etPtr.Error != ""
}

// NewErrorAndTime returns instance of ErrorAndTime with the specified values
func NewErrorAndTime(errStr string, errTime time.Time) ErrorAndTime {
	return ErrorAndTime{Error: errStr, ErrorTime: errTime}
}

// NewErrorAndTimeNow returns instance of ErrorAndTime with the specified values
func NewErrorAndTimeNow(errStr string) ErrorAndTime {
	return ErrorAndTime{Error: errStr, ErrorTime: time.Now()}
}

// ErrorAndTimeWithSource has an additional field "ErrorSourceType"
// which is used to selectively clear errors by calling IsErrorSource before
// calling ClearErrorWithSource. See zedmanager and volumemgr for example use.
type ErrorAndTimeWithSource struct {
	ErrorSourceType interface{}
	Error           string
	ErrorTime       time.Time
}

// SetError - Sets error state with no source type
func (etsPtr *ErrorAndTimeWithSource) SetError(errStr string, errTime time.Time) {
	if errStr == "" {
		log.Fatal("Missing error string")
	}
	etsPtr.Error = errStr
	etsPtr.ErrorSourceType = nil
	etsPtr.ErrorTime = errTime
}

// SetErrorWithSource - Sets error state. Source needs to be a type
func (etsPtr *ErrorAndTimeWithSource) SetErrorWithSource(errStr string,
	source interface{}, errTime time.Time) {

	if !allowedSourceType(source) {
		log.Fatalf("Bad ErrorSourceType %T", source)
	}
	if errStr == "" {
		log.Fatal("Missing error string")
	}
	etsPtr.Error = errStr
	etsPtr.ErrorSourceType = source
	etsPtr.ErrorTime = errTime
}

// IsErrorSource returns true if the source type matches
func (etsPtr *ErrorAndTimeWithSource) IsErrorSource(source interface{}) bool {
	if !allowedSourceType(source) {
		log.Fatalf("Bad ErrorSourceType %T", source)
	}
	if !etsPtr.HasError() {
		return false
	}
	return reflect.TypeOf(source) == reflect.TypeOf(etsPtr.ErrorSourceType)
}

// ClearErrorWithSource - Clears error state
func (etsPtr *ErrorAndTimeWithSource) ClearErrorWithSource() {
	etsPtr.Error = ""
	etsPtr.ErrorSourceType = nil
	etsPtr.ErrorTime = time.Time{}
}

// HasError returns true if there is an error
func (etsPtr *ErrorAndTimeWithSource) HasError() bool {
	return etsPtr.Error != ""
}

// ErrorAndTime returns instance of ErrorAndTime corresponding to
//  Error and ErrorTime in the instance of ErrorAndTimeWithSource
func (etsPtr *ErrorAndTimeWithSource) ErrorAndTime() ErrorAndTime {
	return NewErrorAndTime(etsPtr.Error, etsPtr.ErrorTime)
}

// Disallow leaf types and pointers, since pointers
// and their struct types do not compare as equal
func allowedSourceType(source interface{}) bool {
	// Catch common mistakes like a string
	switch source.(type) {
	case int:
		return false
	case string:
		return false
	case bool:
		return false
	}
	val := reflect.ValueOf(source)
	if val.Kind() == reflect.Ptr {
		return false
	}
	return true
}
