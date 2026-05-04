// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// ProcessMetric.Key / LogKey

func TestProcessMetricLogKey(t *testing.T) {
	m := ProcessMetric{Pid: 1234}
	assert.Equal(t, "1234", m.Key())
	assert.Contains(t, m.LogKey(), "1234")
}

// ProcessMetric LogCreate / LogModify / LogDelete

func TestProcessMetricLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	m := ProcessMetric{Pid: 42}
	m.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	m.LogModify(log, m)
	m.LogDelete(log)
}
