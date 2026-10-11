// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package volumehandlers

import (
	"errors"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
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
		state         kubeapi.PVCUploadState
		lookupErr     error
		wantCreated   bool
	}{
		{
			name:          "upload complete reports created",
			referenceName: "some-image-ref",
			state:         kubeapi.PVCUploadComplete,
			wantCreated:   true,
		},
		{
			// The PVC is bound so it attaches and the domain boots, but CDI
			// never finished writing the image.
			name:          "upload incomplete refuses to report created",
			referenceName: "some-image-ref",
			state:         kubeapi.PVCUploadIncomplete,
		},
		{
			name:          "image volume with no upload refuses to report created",
			referenceName: "some-image-ref",
			state:         kubeapi.PVCNoUpload,
		},
		{
			// Cannot confirm is not the same as confirmed, and keeping the
			// app down is the safe direction.
			name:          "unconfirmable upload refuses to report created",
			referenceName: "some-image-ref",
			lookupErr:     errors.New("apiserver unreachable"),
		},
		{
			// A blank volume (the CreatePVC path) was never given content to
			// upload, so there is nothing to confirm for it.
			name:        "blank PVC reports created",
			state:       kubeapi.PVCNoUpload,
			wantCreated: true,
		},
		{
			// A volume without an image reference can still be filled by an
			// upload, e.g. from a disk file; a partial one must not be used.
			name:  "incomplete upload with no reference name refuses to report created",
			state: kubeapi.PVCUploadIncomplete,
		},
		{
			// The create worker has just reported success, and a blank
			// volume must not be parked on a transient API error.
			name:        "unknown upload state with no reference name reports created",
			lookupErr:   errors.New("apiserver unreachable"),
			wantCreated: true,
		},
		{
			name:        "complete upload with no reference name reports created",
			state:       kubeapi.PVCUploadComplete,
			wantCreated: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockUploadState(t, tc.state, tc.lookupErr)

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
			if tc.wantCreated {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestCSIHandler_KvmCarriedZvolLookup covers where a PVC's source is looked for
// on a ZFS /persist converted from EVE-kvm: the encrypted zvols in the parked
// kvm vault, the clear ones in place, and never an empty PVC while a carried
// zvol exists without its device node.
func TestCSIHandler_KvmCarriedZvolLookup(t *testing.T) {
	volumeID := uuid.FromStringOrNil("6f6d2f2a-6b5e-4d0a-9b52-3f2f7d9c1a10")
	parked := "persist/vault.old/volumes/" + volumeID.String() + ".3"
	clearZvol := "persist/clear/volumes/" + volumeID.String() + ".3"
	tests := []struct {
		name        string
		encrypted   bool
		zfs         bool
		zvolExists  bool
		wantDataset string
		wantErr     bool
	}{
		{name: "encrypted zvol in the parked kvm vault", encrypted: true, zfs: true,
			zvolExists: true, wantDataset: parked, wantErr: true},
		{name: "clear zvol in place", zfs: true, zvolExists: true,
			wantDataset: clearZvol, wantErr: true},
		{name: "no carried zvol", encrypted: true, zfs: true, wantDataset: parked},
		{name: "ext4 persist", encrypted: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origZFS, origExists := persistIsZFS, zvolDatasetExists
			defer func() { persistIsZFS, zvolDatasetExists = origZFS, origExists }()
			var looked []string
			persistIsZFS = func() bool { return tc.zfs }
			zvolDatasetExists = func(_ *base.LogObject, dataset string) bool {
				looked = append(looked, dataset)
				return tc.zvolExists
			}

			status := types.VolumeStatus{
				VolumeID:               volumeID,
				GenerationCounter:      2,
				LocalGenerationCounter: 1,
				Encrypted:              tc.encrypted,
			}
			handler := &volumeHandlerCSI{commonVolumeHandler: commonVolumeHandler{
				status: &status,
				log:    newTestLog(t),
			}}

			// No /dev/zvol exists here, so a carried zvol must surface as an
			// error rather than as "no source".
			src, err := handler.kvmMigratedSourcePath()
			assert.Empty(t, src)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			if tc.wantDataset == "" {
				assert.Empty(t, looked)
			} else {
				assert.Equal(t, []string{tc.wantDataset}, looked)
			}
		})
	}
}

// TestCSIHandler_PopulateRejectsPartialUpload covers the reboot path: volumemgr
// adopts a PVC left from the previous boot through Populate, and a PVC whose
// upload was cut short by that reboot must go back through the create path,
// which re-drives the upload, rather than be reported created.
func TestCSIHandler_PopulateRejectsPartialUpload(t *testing.T) {
	tests := []struct {
		name        string
		state       kubeapi.PVCUploadState
		lookupErr   error
		wantCreated bool
	}{
		{
			name:        "complete upload is adopted",
			state:       kubeapi.PVCUploadComplete,
			wantCreated: true,
		},
		{
			name:        "blank PVC is adopted",
			state:       kubeapi.PVCNoUpload,
			wantCreated: true,
		},
		{
			name:  "incomplete upload is not adopted",
			state: kubeapi.PVCUploadIncomplete,
		},
		{
			name:      "unknown upload state is not adopted",
			lookupErr: errors.New("apiserver unreachable"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origFind := findPVC
			findPVC = func(string, *base.LogObject) (bool, error) { return true, nil }
			defer func() { findPVC = origFind }()
			mockUploadState(t, tc.state, tc.lookupErr)

			status := types.VolumeStatus{}
			handler := NewCSIHandler(commonVolumeHandler{
				volumeManager: &mockVolumeMgr{},
				status:        &status,
				log:           newTestLog(t),
			}, false)

			created, err := handler.Populate()
			assert.NoError(t, err)
			assert.Equal(t, tc.wantCreated, created)
		})
	}
}

// mockUploadState makes pvcUploadState return state and err for the rest of
// the test.
func mockUploadState(t *testing.T, state kubeapi.PVCUploadState, err error) {
	orig := pvcUploadState
	pvcUploadState = func(string, *base.LogObject) (kubeapi.PVCUploadState, error) {
		return state, err
	}
	t.Cleanup(func() { pvcUploadState = orig })
}
