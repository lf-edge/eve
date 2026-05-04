// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
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

// DiskMetric / AppDiskMetric LogCreate / LogModify / LogDelete

func TestDiskMetricLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	m := DiskMetric{DiskPath: "/persist/img"}
	m.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	m.LogModify(log, m)
	m.LogDelete(log)
}

func TestAppDiskMetricLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	m := AppDiskMetric{DiskPath: "/persist/volumes/vol1"}
	m.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	m.LogModify(log, m)
	m.LogDelete(log)
}
