// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package volumehandlers

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
)

// TestCSIHandler_UsageFromStatus mirrors TestCommonHandler_UsageFromStatus.
// The nil-config, ReadOnly, and no-refs cases FAIL before the fix in
// csihandler.go because the handler unconditionally returns MaxVolSize.
// The active-writable case passes both before and after the fix.
func TestCSIHandler_UsageFromStatus(t *testing.T) {
	const (
		currentSize int64  = 1024
		maxVolSize  uint64 = 4096
	)

	tests := []struct {
		name     string
		status   types.VolumeStatus
		config   *types.VolumeConfig
		expected uint64
	}{
		{
			name:     "nil VolumeConfig returns CurrentSize",
			status:   types.VolumeStatus{CurrentSize: currentSize, MaxVolSize: maxVolSize},
			config:   nil,
			expected: uint64(currentSize),
		},
		{
			name:     "ReadOnly returns CurrentSize",
			status:   types.VolumeStatus{CurrentSize: currentSize, MaxVolSize: maxVolSize, ReadOnly: true},
			config:   &types.VolumeConfig{},
			expected: uint64(currentSize),
		},
		{
			name:     "HasNoAppReferences returns CurrentSize",
			status:   types.VolumeStatus{CurrentSize: currentSize, MaxVolSize: maxVolSize},
			config:   &types.VolumeConfig{HasNoAppReferences: true},
			expected: uint64(currentSize),
		},
		{
			name:     "active writable returns MaxVolSize",
			status:   types.VolumeStatus{CurrentSize: currentSize, MaxVolSize: maxVolSize},
			config:   &types.VolumeConfig{},
			expected: maxVolSize,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewCSIHandler(commonVolumeHandler{
				volumeManager: &mockVolumeMgr{config: tc.config},
				status:        &tc.status,
				log:           newTestLog(t),
			}, false)
			assert.Equal(t, tc.expected, handler.UsageFromStatus())
		})
	}
}
