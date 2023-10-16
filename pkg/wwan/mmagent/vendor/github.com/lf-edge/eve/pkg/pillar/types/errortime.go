// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"reflect"
	"time"

	"github.com/sirupsen/logrus" // OK for logrus.Fatal
)

const (
	//RetryCountWarning indicates to move severity to Warning in case of more retries
	RetryCountWarning = 10
	//RetryTimeWarning indicates to move severity to Warning in case of more time spent for retry
	RetryTimeWarning = time.Hour
	//RetryCountError indicates to move severity to Error in case of more retries
	RetryCountError = 20
	//RetryTimeError indicates to move severity to Error in case of more time spent for retry
	RetryTimeError = 10 * time.Hour
)

// ErrorSeverity tells the severity type, must be in sync with info.Severity enum of api
type ErrorSeverity int32

const (
	// ErrorSeverityUnspecified severity unspecified
	ErrorSeverityUnspecified ErrorSeverity = 0
	// ErrorSeverityNotice severity notice
	ErrorSeverityNotice ErrorSeverity = 1
	// ErrorSeverityWarning severity warning
	ErrorSeverityWarning ErrorSeverity = 2
	// ErrorSeverityError severity error
	ErrorSeverityError ErrorSeverity = 3
)

// GetErrorSeverity returns ErrorSeverity based on retry count and time spend
func GetErrorSeverity(retryCount int, timeSpend time.Duration) ErrorSeverity {
	if retryCount > RetryCountError || timeSpend > RetryTimeError {
		return ErrorSeverityError
	}
	if retryCount > RetryCountWarning || timeSpend > RetryTimeWarning {
		return ErrorSeverityWarning
	}
	return ErrorSeverityNotice
}

// ErrorEntityType contains the entity type, must be in sync with info.Entity enum of api
type ErrorEntityType int32

const (
	// ErrorEntityUnspecified Entity
	ErrorEntityUnspecified ErrorEntityType = 0
	// ErrorEntityBaseOs entity
	ErrorEntityBaseOs ErrorEntityType = 1
	// ErrorEntitySystemAdapter Entity
	ErrorEntitySystemAdapter ErrorEntityType = 2
	// ErrorEntityVault Entity
	ErrorEntityVault ErrorEntityType = 3
	// ErrorEntityAttestation Entity
	ErrorEntityAttestation ErrorEntityType = 4
	// ErrorEntityAppInstance Entity
	ErrorEntityAppInstance ErrorEntityType = 5
	// ErrorEntityPort Entity
	ErrorEntityPort ErrorEntityType = 6
	// ErrorEntityNetwork Entity
	ErrorEntityNetwork ErrorEntityType = 7
	// ErrorEntityNetworkInstance Entity
	ErrorEntityNetworkInstance ErrorEntityType = 8
	// ErrorEntityContentTree Entity
	ErrorEntityContentTree ErrorEntityType = 9
	// ErrorEntityContentBlob Entity
	ErrorEntityContentBlob ErrorEntityType = 10
	// ErrorEntityVolume Entity
	ErrorEntityVolume ErrorEntityType = 11
)

// ErrorEntity contains the device entity details
type ErrorEntity struct {
	EntityType ErrorEntityType // entity type
	EntityID   string          // entity uuid, sha, or other unique id based on the type
}

// ErrorDescription contains error details
type ErrorDescription struct {
	Error               string
	ErrorTime           time.Time
	ErrorSeverity       ErrorSeverity
	ErrorRetryCondition string
	ErrorEntities       []*ErrorEntity
}

// SetErrorDescription sync ErrorDescription with provided one
// it sets ErrorSeverityError in case of unspecified ErrorSeverity
// it sets ErrorTime to time.Now() in case of no time provided
func (edPtr *ErrorDescription) SetErrorDescription(errDescription ErrorDescription) {
	if errDescription.Error == "" {
		logrus.Fatal("Missing error string")
	}
	*edPtr = errDescription
	if edPtr.ErrorSeverity == ErrorSeverityUnspecified {
		edPtr.ErrorSeverity = ErrorSeverityError
	}
	if edPtr.ErrorTime.IsZero() {
		edPtr.ErrorTime = time.Now()
	}
}

// ErrorAndTime is used by many EVE agents
type ErrorAndTime struct {
	ErrorDescription
}

// SetErrorNow uses the current time
// Deprecated: use SetErrorDescription instead with ErrorDescription without ErrorTime inside (or with zero time)
func (etPtr *ErrorAndTime) SetErrorNow(errStr string) {
	etPtr.SetError(errStr, time.Now())
}

// SetError is when time is specified
// Deprecated: use SetErrorDescription instead with ErrorDescription
func (etPtr *ErrorAndTime) SetError(errStr string, errorTime time.Time) {
	description := ErrorDescription{
		Error:     errStr,
		ErrorTime: errorTime,
	}
	etPtr.SetErrorDescription(description)
}

// ClearError removes it
func (etPtr *ErrorAndTime) ClearError() {
	etPtr.Error = ""
	etPtr.ErrorTime = time.Time{}
	etPtr.ErrorRetryCondition = ""
	etPtr.ErrorSeverity = ErrorSeverityUnspecified
	etPtr.ErrorEntities = []*ErrorEntity{}
}

// HasError returns true if there is an error
func (etPtr *ErrorAndTime) HasError() bool {
	return etPtr.Error != ""
}

// ErrorAndTimeWithSource has an additional field "ErrorSourceType"
// which is used to selectively clear errors by calling IsErrorSource before
// calling ClearErrorWithSource. See zedmanager and volumemgr for example use.
type ErrorAndTimeWithSource struct {
	ErrorSourceType string
	ErrorDescription
}

// SetError - Sets error state with no source type
// Deprecated: use SetErrorDescription instead with ErrorDescription
func (etsPtr *ErrorAndTimeWithSource) SetError(errStr string, errTime time.Time) {
	description := ErrorDescription{
		Error:     errStr,
		ErrorTime: errTime,
	}
	etsPtr.SetErrorDescription(description)
}

// SetErrorWithSource - Sets error state. Source needs to be a type
// but source might be a string passed from ErrorSourceType in another
// object.
// Deprecated: use SetErrorWithSourceAndDescription instead with ErrorDescription
func (etsPtr *ErrorAndTimeWithSource) SetErrorWithSource(errStr string,
	source interface{}, errTime time.Time) {

	if !allowedSourceType(source) {
		logrus.Fatalf("Bad ErrorSourceType %T", source)
	}
	description := ErrorDescription{
		Error:     errStr,
		ErrorTime: errTime,
	}
	etsPtr.SetErrorDescription(description)
	switch source.(type) {
	case string:
		etsPtr.ErrorSourceType = source.(string)
	default:
		etsPtr.ErrorSourceType = reflect.TypeOf(source).String()
	}
}

// SetErrorWithSourceAndDescription - Sets error state with ErrorDescription. Source needs to be a type
// but source might be a string passed from ErrorSourceType in another object.
func (etsPtr *ErrorAndTimeWithSource) SetErrorWithSourceAndDescription(errDescription ErrorDescription,
	source interface{}) {

	if !allowedSourceType(source) {
		logrus.Fatalf("Bad ErrorSourceType %T", source)
	}
	etsPtr.SetErrorDescription(errDescription)
	switch source.(type) {
	case string:
		etsPtr.ErrorSourceType = source.(string)
	default:
		etsPtr.ErrorSourceType = reflect.TypeOf(source).String()
	}
}

// IsErrorSource returns true if the source type matches
func (etsPtr *ErrorAndTimeWithSource) IsErrorSource(source interface{}) bool {
	if !allowedSourceType(source) {
		logrus.Fatalf("Bad ErrorSourceType %T", source)
	}
	if !etsPtr.HasError() {
		return false
	}
	return reflect.TypeOf(source).String() == etsPtr.ErrorSourceType
}

// ClearErrorWithSource - Clears error state
func (etsPtr *ErrorAndTimeWithSource) ClearErrorWithSource() {
	etsPtr.Error = ""
	etsPtr.ErrorSourceType = ""
	etsPtr.ErrorTime = time.Time{}
	etsPtr.ErrorRetryCondition = ""
	etsPtr.ErrorSeverity = ErrorSeverityUnspecified
	etsPtr.ErrorEntities = []*ErrorEntity{}
}

// HasError returns true if there is an error
func (etsPtr *ErrorAndTimeWithSource) HasError() bool {
	return etsPtr.Error != ""
}

// Disallow leaf types and pointers, since pointers
// and their struct types do not compare as equal
// Allow string in case passed from another ErrorSourceType
func allowedSourceType(source interface{}) bool {
	switch source.(type) {
	case int:
		return false
	case string:
		return true
	case bool:
		return false
	}
	if _, ok := source.(map[string]interface{}); ok {
		return false
	}
	val := reflect.ValueOf(source)
	if val.Kind() == reflect.Ptr {
		return false
	}
	return true
}
