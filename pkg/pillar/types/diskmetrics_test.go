// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// PathToKey

func TestPathToKey(t *testing.T) {
	assert.Equal(t, "a-b-c", PathToKey("/a/b/c"))
	assert.Equal(t, "a-b-c", PathToKey("a/b/c"))
	assert.Equal(t, "foo", PathToKey("/foo"))
	assert.Equal(t, "foo", PathToKey("foo"))
	assert.Equal(t, "", PathToKey("/"))
	assert.Equal(t, "", PathToKey(""))
}

// DiskMetric.Key / LogKey

func TestDiskMetricLogKey(t *testing.T) {
	m := DiskMetric{DiskPath: "/dev/sda"}
	assert.Equal(t, PathToKey("/dev/sda"), m.Key())
	assert.Contains(t, m.LogKey(), m.Key())
}

// AppDiskMetric.Key / LogKey

func TestAppDiskMetricLogKey(t *testing.T) {
	m := AppDiskMetric{DiskPath: "/persist/volumes/vol1"}
	assert.Equal(t, PathToKey("/persist/volumes/vol1"), m.Key())
	assert.Contains(t, m.LogKey(), m.Key())
}
