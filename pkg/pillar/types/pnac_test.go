// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// PNACMetricsList.Key

func TestPNACMetricsListKey(t *testing.T) {
	assert.Equal(t, "global", PNACMetricsList{}.Key())
}
