// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddrErrorsEmpty(t *testing.T) {
	var errs addrErrors
	assert.True(t, errs.empty())
	assert.Equal(t, "", errs.String())
}

func TestAddrErrorsReportsTheSameFailureOnceWithItsAddresses(t *testing.T) {
	var errs addrErrors
	errs.add("10.0.0.1", errors.New("GET https://r/v2/x/blobs/sha256:a: BLOB_UNKNOWN: Unknown blob"))
	errs.add("10.0.0.2", errors.New("GET https://r/v2/x/blobs/sha256:a: BLOB_UNKNOWN: Unknown blob"))
	got := errs.String()
	assert.False(t, errs.empty())
	assert.Equal(t, 1, strings.Count(got, "BLOB_UNKNOWN"), got)
	assert.Contains(t, got, "10.0.0.1")
	assert.Contains(t, got, "10.0.0.2")
}

func TestAddrErrorsKeepsDistinctFailuresInOrder(t *testing.T) {
	var errs addrErrors
	errs.add("10.0.0.1", errors.New("i/o timeout"))
	errs.add("10.0.0.2", errors.New("connection refused"))
	got := errs.String()
	assert.Less(t, strings.Index(got, "i/o timeout"),
		strings.Index(got, "connection refused"), got)
}

func TestAddrErrorsWithoutAnAddress(t *testing.T) {
	var errs addrErrors
	errs.add("", errors.New("no addresses"))
	assert.Equal(t, "no addresses", errs.String())
}

func TestAddrErrorsStayWithinTheBound(t *testing.T) {
	var errs addrErrors
	for i := 0; i < 20; i++ {
		errs.add(fmt.Sprintf("10.0.0.%d", i),
			fmt.Errorf("%d: %s", i, strings.Repeat("x", 600)))
	}
	got := errs.String()
	assert.LessOrEqual(t, len(got), maxAddrErrorsLen)
	assert.Contains(t, got, "more")
}
