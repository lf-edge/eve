// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetTimestampFromGzipName

func TestGetTimestampFromGzipName(t *testing.T) {
	// dev.log.upload.1730404601953.gz — timestamp in milliseconds
	ts, err := GetTimestampFromGzipName("dev.log.upload.1730404601953.gz")
	require.NoError(t, err)
	expected := time.Unix(0, 1730404601953*int64(time.Millisecond))
	assert.Equal(t, expected, ts)

	// app file with UUID in name
	ts, err = GetTimestampFromGzipName("app.6656f860-7563-4bbf-8bba-051f5942982b.log.1730464687367.gz")
	require.NoError(t, err)
	expected = time.Unix(0, 1730464687367*int64(time.Millisecond))
	assert.Equal(t, expected, ts)

	// Invalid: too few parts
	_, err = GetTimestampFromGzipName("nogz")
	assert.Error(t, err)

	// Invalid: non-numeric timestamp part
	_, err = GetTimestampFromGzipName("dev.log.upload.notanumber.gz")
	assert.Error(t, err)
}
