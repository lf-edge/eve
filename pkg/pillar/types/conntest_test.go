// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTestResultsRecordSuccess(t *testing.T) {
	var tr TestResults
	before := time.Now()
	tr.RecordSuccess()
	after := time.Now()

	assert.True(t, tr.LastSucceeded.After(before) || tr.LastSucceeded.Equal(before))
	assert.True(t, tr.LastSucceeded.Before(after) || tr.LastSucceeded.Equal(after))
	assert.Equal(t, "", tr.LastError)
	assert.Equal(t, "", tr.LastWarning)
	assert.False(t, tr.HasError())
}

func TestTestResultsRecordSuccessWithWarning(t *testing.T) {
	var tr TestResults
	tr.RecordSuccessWithWarning("potential issue")

	assert.Equal(t, "", tr.LastError)
	assert.Equal(t, "potential issue", tr.LastWarning)
	assert.False(t, tr.HasError())
	assert.True(t, tr.HasWarning())
}

func TestTestResultsRecordFailure(t *testing.T) {
	var tr TestResults
	before := time.Now()
	tr.RecordFailure("something failed")
	after := time.Now()

	assert.True(t, tr.LastFailed.After(before) || tr.LastFailed.Equal(before))
	assert.True(t, tr.LastFailed.Before(after) || tr.LastFailed.Equal(after))
	assert.Equal(t, "something failed", tr.LastError)
	assert.Equal(t, "", tr.LastWarning)
	assert.True(t, tr.HasError())
}

func TestTestResultsHasError(t *testing.T) {
	var tr TestResults
	// Never tested: both zero — no error
	assert.False(t, tr.HasError())

	// Only succeeded
	tr.RecordSuccess()
	assert.False(t, tr.HasError())

	// Fail after succeed
	tr.RecordFailure("oops")
	assert.True(t, tr.HasError())

	// Succeed after fail
	tr.RecordSuccess()
	assert.False(t, tr.HasError())
}

func TestTestResultsHasWarning(t *testing.T) {
	var tr TestResults
	assert.False(t, tr.HasWarning())

	tr.RecordSuccessWithWarning("warn")
	assert.True(t, tr.HasWarning())

	// After failure, no warning even if LastWarning has residual
	tr.RecordFailure("err")
	assert.False(t, tr.HasWarning())

	tr.RecordSuccess()
	assert.False(t, tr.HasWarning())
}

func TestTestResultsUpdateSrcHasError(t *testing.T) {
	var dst TestResults
	dst.RecordSuccess()
	savedSucceeded := dst.LastSucceeded

	var src TestResults
	src.RecordFailure("src error")

	dst.Update(src)

	assert.Equal(t, src.LastFailed, dst.LastFailed)
	assert.Equal(t, "src error", dst.LastError)
	assert.Equal(t, "", dst.LastWarning)
	// src.LastSucceeded is zero, dst kept its own
	assert.Equal(t, savedSucceeded, dst.LastSucceeded)
	assert.True(t, dst.HasError())
}

func TestTestResultsUpdateSrcNoError(t *testing.T) {
	var dst TestResults
	dst.RecordFailure("old error")
	savedFailed := dst.LastFailed

	var src TestResults
	src.RecordSuccessWithWarning("warn msg")

	dst.Update(src)

	assert.Equal(t, src.LastSucceeded, dst.LastSucceeded)
	assert.Equal(t, "", dst.LastError)
	assert.Equal(t, "warn msg", dst.LastWarning)
	// src.LastFailed is zero, dst kept its own
	assert.Equal(t, savedFailed, dst.LastFailed)
}

func TestTestResultsUpdateSrcNewerSucceeded(t *testing.T) {
	var dst TestResults
	dst.RecordFailure("err")

	var src TestResults
	src.RecordFailure("src err")
	// Also give src a more recent succeeded
	src.LastSucceeded = time.Now().Add(time.Hour)

	dst.Update(src)
	assert.Equal(t, src.LastSucceeded, dst.LastSucceeded)
}

func TestTestResultsUpdateSrcNewerFailed(t *testing.T) {
	var dst TestResults
	dst.RecordSuccess()

	var src TestResults
	src.RecordSuccess()
	// Give src an older failure
	src.LastFailed = time.Now().Add(-time.Hour)

	dst.Update(src)
	// dst.LastFailed was zero, src has an older failure — should be adopted
	assert.Equal(t, src.LastFailed, dst.LastFailed)
}

func TestTestResultsClear(t *testing.T) {
	var tr TestResults
	tr.RecordFailure("err")
	tr.Clear()

	assert.True(t, tr.LastFailed.IsZero())
	assert.True(t, tr.LastSucceeded.IsZero())
	assert.Equal(t, "", tr.LastError)
	assert.Equal(t, "", tr.LastWarning)
	assert.False(t, tr.HasError())
}

// TestTestResultsUpdateSrcHasErrorNewerSucceeded covers the branch where src has an
// error AND src.LastSucceeded is after dst.LastSucceeded (S6 in Update).
func TestTestResultsUpdateSrcHasErrorNewerSucceeded(t *testing.T) {
	var dst TestResults
	// dst.LastSucceeded stays zero

	var src TestResults
	src.LastSucceeded = time.Now()
	src.LastFailed = time.Now().Add(time.Second) // LastFailed after LastSucceeded → HasError=true

	dst.Update(src)
	assert.Equal(t, src.LastSucceeded, dst.LastSucceeded)
}

func TestIntfStatusMapRecordSuccess(t *testing.T) {
	m := NewIntfStatusMap()
	m.RecordSuccess("eth0")

	tr, ok := m.StatusMap["eth0"]
	assert.True(t, ok)
	assert.False(t, tr.HasError())
	assert.False(t, tr.LastSucceeded.IsZero())
}

func TestIntfStatusMapRecordFailure(t *testing.T) {
	m := NewIntfStatusMap()
	m.RecordFailure("eth0", "link down")

	tr, ok := m.StatusMap["eth0"]
	assert.True(t, ok)
	assert.True(t, tr.HasError())
	assert.Equal(t, "link down", tr.LastError)
}

func TestIntfStatusMapRecordSuccessWithWarning(t *testing.T) {
	m := NewIntfStatusMap()
	m.RecordSuccessWithWarning("eth0", "slow link")

	tr, ok := m.StatusMap["eth0"]
	assert.True(t, ok)
	assert.True(t, tr.HasWarning())
	assert.Equal(t, "slow link", tr.LastWarning)
}

func TestIntfStatusMapSetOrUpdateFromMap(t *testing.T) {
	dst := NewIntfStatusMap()
	dst.RecordSuccess("eth0")

	src := NewIntfStatusMap()
	src.RecordFailure("eth0", "timeout")
	src.RecordSuccess("eth1")

	dst.SetOrUpdateFromMap(*src)

	// eth0 should now reflect the failure from src
	tr0 := dst.StatusMap["eth0"]
	assert.True(t, tr0.HasError())

	// eth1 was only in src — should be added
	tr1, ok := dst.StatusMap["eth1"]
	assert.True(t, ok)
	assert.False(t, tr1.HasError())
}
