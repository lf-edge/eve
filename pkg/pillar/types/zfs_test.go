// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

// VolumeStatus.ZVolName

func TestVolumeStatusZVolName(t *testing.T) {
	id := uuid.Must(uuid.NewV4())

	// Non-encrypted: uses VolumeClearZFSDataset
	s := VolumeStatus{VolumeID: id, GenerationCounter: 2, LocalGenerationCounter: 1}
	got := s.ZVolName()
	assert.Equal(t, fmt.Sprintf("%s/%s.3", VolumeClearZFSDataset, id.String()), got)

	// Encrypted: uses VolumeEncryptedZFSDataset
	s.Encrypted = true
	got = s.ZVolName()
	assert.Equal(t, fmt.Sprintf("%s/%s.3", VolumeEncryptedZFSDataset, id.String()), got)
}

// VolumeCreatePending.ZVolName

func TestVolumeCreatePendingZVolName(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	vcp := VolumeCreatePending{VolumeID: id, GenerationCounter: 0}
	got := vcp.ZVolName()
	assert.Equal(t, fmt.Sprintf("%s/%s.0", VolumeClearZFSDataset, id.String()), got)

	// Encrypted: uses VolumeEncryptedZFSDataset
	vcp.Encrypted = true
	got = vcp.ZVolName()
	assert.Equal(t, fmt.Sprintf("%s/%s.0", VolumeEncryptedZFSDataset, id.String()), got)
}

// ZVolStatus.Key

func TestZVolStatusKey(t *testing.T) {
	s := ZVolStatus{Dataset: "pool/vol/data"}
	assert.Equal(t, "pool_vol_data", s.Key())

	s2 := ZVolStatus{Dataset: "simple"}
	assert.Equal(t, "simple", s2.Key())
}

// VolumeStatus.UseZVolDisk

func TestVolumeStatusUseZVolDisk(t *testing.T) {
	// Container: always false
	s := VolumeStatus{ContentFormat: zconfig.Format_CONTAINER}
	assert.False(t, s.UseZVolDisk(PersistZFS))

	// ISO: always false
	s = VolumeStatus{ContentFormat: zconfig.Format_ISO}
	assert.False(t, s.UseZVolDisk(PersistZFS))

	// Raw + ZFS → true
	s = VolumeStatus{ContentFormat: zconfig.Format_RAW}
	assert.True(t, s.UseZVolDisk(PersistZFS))

	// Raw + non-ZFS → false
	assert.False(t, s.UseZVolDisk(PersistExt4))
}
