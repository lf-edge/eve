// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package volumehandlers

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
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

// TestCSIHandler_HandleCreatedRequiresUpload covers the content check that
// keeps a volume below CREATED_VOLUME -- the state zedmanager gates app
// activation on -- until CDI confirms the image actually landed in the PVC.
// A PVC binds and attaches whether or not anything was ever written into it,
// so the create worker returning is not evidence the app has a disk to boot.
func TestCSIHandler_HandleCreatedRequiresUpload(t *testing.T) {
	const maxVolSize uint64 = 4096

	tests := []struct {
		name          string
		referenceName string
		uploaded      bool
		lookupErr     error
		wantCreated   bool
		wantErr       bool
		wantLookup    bool
	}{
		{
			name:          "upload complete reports created",
			referenceName: "some-image-ref",
			uploaded:      true,
			wantCreated:   true,
			wantLookup:    true,
		},
		{
			// The live failure this exists for: the PVC is bound so it
			// attaches and the domain boots, but CDI never wrote the image.
			name:          "upload incomplete refuses to report created",
			referenceName: "some-image-ref",
			wantErr:       true,
			wantLookup:    true,
		},
		{
			// Cannot confirm is not the same as confirmed, and keeping the
			// app down is the safe direction.
			name:          "unconfirmable upload refuses to report created",
			referenceName: "some-image-ref",
			lookupErr:     errors.New("apiserver unreachable"),
			wantErr:       true,
			wantLookup:    true,
		},
		{
			// A blank volume (the CreatePVC path) was never given content to
			// upload, so there is nothing to confirm for it.
			name:        "no reference name skips the check",
			wantCreated: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			orig := pvcUploadComplete
			pvcUploadComplete = func(string, *base.LogObject) (bool, error) {
				called = true
				return tc.uploaded, tc.lookupErr
			}
			defer func() { pvcUploadComplete = orig }()

			// MaxVolSize is set so updateVolumeSizes has nothing to ask the
			// cluster for on the paths that get that far.
			status := types.VolumeStatus{
				MaxVolSize:    maxVolSize,
				ReferenceName: tc.referenceName,
			}
			handler := NewCSIHandler(commonVolumeHandler{
				volumeManager: &mockVolumeMgr{},
				status:        &status,
				log:           newTestLog(t),
			}, false)

			created, err := handler.HandleCreated()
			assert.Equal(t, tc.wantCreated, created)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.wantLookup, called,
				"upload check consulted = %v, want %v", called, tc.wantLookup)
		})
	}
}
