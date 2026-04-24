// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ENClusterAppStatus.Equal

func TestENClusterAppStatusEqual(t *testing.T) {
	s1 := ENClusterAppStatus{
		ScheduledOnThisNode: true,
		StatusRunning:       false,
		AppIsVMI:            true,
		VMIName:             "myapp",
		VNCPort:             5901,
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.ScheduledOnThisNode = false
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.VMIName = "otherapp"
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.VNCPort = 5902
	assert.False(t, s1.Equal(s2))
}
