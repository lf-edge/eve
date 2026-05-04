// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ZbootConfig.Key / LogKey

func TestZbootConfigLogKey(t *testing.T) {
	cfg := ZbootConfig{PartitionLabel: "IMGA"}
	assert.Equal(t, "IMGA", cfg.Key())
	assert.Contains(t, cfg.LogKey(), "IMGA")
}

// ZbootStatus.Key / LogKey

func TestZbootStatusLogKey(t *testing.T) {
	status := ZbootStatus{PartitionLabel: "IMGB", ShortVersion: "1.0.0"}
	assert.Equal(t, "IMGB", status.Key())
	assert.Contains(t, status.LogKey(), "IMGB")
}
