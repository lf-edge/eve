// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumehandlers

import (
	"io"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// mockVolumeMgr satisfies VolumeMgr for handler unit tests.
// Only LookupVolumeConfig has meaningful behaviour; all others return nil.
type mockVolumeMgr struct {
	config *types.VolumeConfig
}

func (m *mockVolumeMgr) LookupVolumeConfig(_ string) *types.VolumeConfig {
	return m.config
}
func (m *mockVolumeMgr) LookupVolumeStatus(_ string) *types.VolumeStatus {
	return nil
}
func (m *mockVolumeMgr) LookupContentTreeStatus(_ string) *types.ContentTreeStatus {
	return nil
}
func (m *mockVolumeMgr) LookupBlobStatus(_ string) *types.BlobStatus {
	return nil
}
func (m *mockVolumeMgr) LookupZVolStatusByDataset(_ string) *types.ZVolStatus {
	return nil
}
func (m *mockVolumeMgr) GetCapabilities() *types.Capabilities {
	return nil
}
func (m *mockVolumeMgr) GetCasClient() cas.CAS {
	return nil
}

func newTestLog(t *testing.T) *base.LogObject {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
}

func TestCommonHandler_UsageFromStatus(t *testing.T) {
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
			handler := &commonVolumeHandler{
				volumeManager: &mockVolumeMgr{config: tc.config},
				status:        &tc.status,
				log:           newTestLog(t),
			}
			assert.Equal(t, tc.expected, handler.UsageFromStatus())
		})
	}
}
