// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	"github.com/sirupsen/logrus"
)

// TestResults is used to record when some test Failed or Succeeded.
// All zeros timestamps means it was never tested.
type TestResults struct {
	LastFailed    time.Time
	LastSucceeded time.Time
	LastError     string // Set when LastFailed is updated
}

// RecordSuccess records a success
// Keeps the LastFailed in place as history
func (trPtr *TestResults) RecordSuccess() {
	trPtr.LastSucceeded = time.Now()
	trPtr.LastError = ""
}

// RecordFailure records a failure
// Keeps the LastSucceeded in place as history
func (trPtr *TestResults) RecordFailure(errStr string) {
	if errStr == "" {
		logrus.Fatal("Missing error string")
	}
	trPtr.LastFailed = time.Now()
	trPtr.LastError = errStr
}

// HasError returns true if there is an error
// Returns false if it was never tested i.e., both timestamps zero
func (trPtr *TestResults) HasError() bool {
	return trPtr.LastFailed.After(trPtr.LastSucceeded)
}

// Update uses the src to add info to the results
// If src has newer information for the 'other' part we update that as well.
func (trPtr *TestResults) Update(src TestResults) {
	if src.HasError() {
		trPtr.LastFailed = src.LastFailed
		trPtr.LastError = src.LastError
		if src.LastSucceeded.After(trPtr.LastSucceeded) {
			trPtr.LastSucceeded = src.LastSucceeded
		}
	} else {
		trPtr.LastSucceeded = src.LastSucceeded
		trPtr.LastError = ""
		if src.LastFailed.After(trPtr.LastFailed) {
			trPtr.LastFailed = src.LastFailed
		}
	}
}

// Clear test results.
func (trPtr *TestResults) Clear() {
	trPtr.LastFailed = time.Time{}
	trPtr.LastSucceeded = time.Time{}
	trPtr.LastError = ""
}

// IntfStatusMap - Used to return per-interface test results (success and failures)
//
//	ifName is used as the key
type IntfStatusMap struct {
	// StatusMap -> Key: ifname, Value: TestResults
	StatusMap map[string]TestResults
}

// NewIntfStatusMap - Create a new instance of IntfStatusMap
func NewIntfStatusMap() *IntfStatusMap {
	intfStatusMap := IntfStatusMap{}
	intfStatusMap.StatusMap = make(map[string]TestResults)
	return &intfStatusMap
}

// RecordSuccess records a success for the ifName
func (intfMap *IntfStatusMap) RecordSuccess(ifName string) {
	tr, ok := intfMap.StatusMap[ifName]
	if !ok {
		tr = TestResults{}
	}
	tr.RecordSuccess()
	intfMap.StatusMap[ifName] = tr
}

// RecordFailure records a failure for the ifName
func (intfMap *IntfStatusMap) RecordFailure(ifName string, errStr string) {
	tr, ok := intfMap.StatusMap[ifName]
	if !ok {
		tr = TestResults{}
	}
	tr.RecordFailure(errStr)
	intfMap.StatusMap[ifName] = tr
}

// SetOrUpdateFromMap - Set all the entries from the given per-interface map
// Entries which are not in the source are not modified
func (intfMap *IntfStatusMap) SetOrUpdateFromMap(
	source IntfStatusMap) {
	for intf, src := range source.StatusMap {
		tr, ok := intfMap.StatusMap[intf]
		if !ok {
			tr = TestResults{}
		}
		tr.Update(src)
		intfMap.StatusMap[intf] = tr
	}
}
