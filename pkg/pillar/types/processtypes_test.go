// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ProcessMetric.Key / LogKey

func TestProcessMetricLogKey(t *testing.T) {
	m := ProcessMetric{Pid: 1234}
	assert.Equal(t, "1234", m.Key())
	assert.Contains(t, m.LogKey(), "1234")
}
