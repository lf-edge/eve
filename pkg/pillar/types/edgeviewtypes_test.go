// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// EdgeviewStatus.Key

func TestEdgeviewStatusKey(t *testing.T) {
	assert.Equal(t, "global", EdgeviewStatus{}.Key())
}
