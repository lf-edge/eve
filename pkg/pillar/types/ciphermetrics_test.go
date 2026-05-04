// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// CipherMetrics.Key / LogKey

func TestCipherMetricsLogKey(t *testing.T) {
	m := CipherMetrics{}
	assert.Equal(t, "global", m.Key())
	assert.Contains(t, m.LogKey(), "global")
}
