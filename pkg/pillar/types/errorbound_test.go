// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestTruncateErrorKeepsStringsWithinTheBound(t *testing.T) {
	assert.Equal(t, "", TruncateError("", 10))
	assert.Equal(t, "short", TruncateError("short", 10))
	exact := strings.Repeat("x", 10)
	assert.Equal(t, exact, TruncateError(exact, 10))
}

func TestTruncateErrorKeepsHeadAndTail(t *testing.T) {
	s := "HEAD" + strings.Repeat("-", 1000) + "TAIL"
	got := TruncateError(s, 100)
	assert.LessOrEqual(t, len(got), 100)
	assert.True(t, strings.HasPrefix(got, "HEAD"), got)
	assert.True(t, strings.HasSuffix(got, "TAIL"), got)
	assert.Contains(t, got, "bytes dropped")
}

func TestTruncateErrorCutsAtRuneBoundaries(t *testing.T) {
	s := strings.Repeat("é", 500)
	got := TruncateError(s, 101)
	assert.LessOrEqual(t, len(got), 101)
	assert.True(t, utf8.ValidString(got))
}

func TestJoinErrorsIsStringsJoinWhenEverythingFits(t *testing.T) {
	assert.Equal(t, "", JoinMaxErrorStrings(nil, " / ", 100))
	assert.Equal(t, "one", JoinMaxErrorStrings([]string{"one"}, " / ", 100))
	assert.Equal(t, "one / two / three",
		JoinMaxErrorStrings([]string{"one", "two", "three"}, " / ", 100))

	// Also when the join only just fits: the room the bounded loop keeps
	// for its "... and N more" note must not cost an error.
	long := strings.Repeat("a", 1015)
	assert.Equal(t, long+"\nshort",
		JoinMaxErrorStrings([]string{long, "short"}, "\n", 1024))
	three := []string{strings.Repeat("b", 60), strings.Repeat("c", 30), "x"}
	assert.Equal(t, strings.Join(three, "\n"), JoinMaxErrorStrings(three, "\n", 100))
}

func TestJoinErrorsStopsAtTheBoundAndCountsTheRest(t *testing.T) {
	errs := []string{
		strings.Repeat("a", 40), strings.Repeat("b", 40),
		strings.Repeat("c", 40), strings.Repeat("d", 40),
	}
	got := JoinMaxErrorStrings(errs, "\n", 100)
	assert.LessOrEqual(t, len(got), 100)
	assert.True(t, strings.HasPrefix(got, errs[0]+"\n"+errs[1]), got)
	assert.NotContains(t, got, "ccc")
	assert.Contains(t, got, "and 2 more")
}

func TestJoinErrorsAlwaysKeepsTheFirstError(t *testing.T) {
	errs := []string{"first: " + strings.Repeat("a", 500), strings.Repeat("b", 500)}
	got := JoinMaxErrorStrings(errs, "\n", 100)
	assert.LessOrEqual(t, len(got), 100)
	assert.True(t, strings.HasPrefix(got, "first: "), got)
	assert.Contains(t, got, "bytes dropped")
	assert.Contains(t, got, "and 1 more")
}

func TestSetErrorDescriptionBoundsTheError(t *testing.T) {
	var ed ErrorDescription
	ed.SetErrorDescription(ErrorDescription{Error: strings.Repeat("x", 3*MaxErrorLen)})
	assert.LessOrEqual(t, len(ed.Error), MaxErrorLen)
	assert.Contains(t, ed.Error, "bytes dropped")

	ed.SetErrorDescription(ErrorDescription{Error: "short"})
	assert.Equal(t, "short", ed.Error)
}

func TestAppInstanceStatusTruncateErrors(t *testing.T) {
	long := strings.Repeat("v", 5000)
	status := AppInstanceStatus{
		VolumeRefStatusList: []VolumeRefStatus{{}, {}},
	}
	status.Error = long
	status.VolumeRefStatusList[0].Error = long
	status.VolumeRefStatusList[1].Error = "short"

	status.TruncateErrors(200)

	assert.LessOrEqual(t, len(status.Error), 200)
	assert.LessOrEqual(t, len(status.VolumeRefStatusList[0].Error), 200)
	assert.Equal(t, "short", status.VolumeRefStatusList[1].Error)
}
