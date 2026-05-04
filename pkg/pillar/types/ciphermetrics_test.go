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

// CipherMetrics.Key / LogKey

func TestCipherMetricsLogKey(t *testing.T) {
	m := CipherMetrics{}
	assert.Equal(t, "global", m.Key())
	assert.Contains(t, m.LogKey(), "global")
}

// CipherMetrics LogCreate / LogModify / LogDelete

func TestCipherMetricsLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	m := CipherMetrics{}
	m.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	m.LogModify(log, m)
	m.LogDelete(log)
}
