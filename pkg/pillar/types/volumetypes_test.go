// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"fmt"
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// VolumeStatus.GetPVCName

func TestVolumeStatusGetPVCName(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := VolumeStatus{
		VolumeID:               id,
		GenerationCounter:      2,
		LocalGenerationCounter: 1,
	}
	expected := fmt.Sprintf("%s-pvc-3", id.String())
	assert.Equal(t, expected, status.GetPVCName())
}

func TestVolumeStatusGetPVCNameNoHash(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := VolumeStatus{VolumeID: id}
	name := status.GetPVCName()
	// Kubernetes does not allow '#' in object names
	assert.NotContains(t, name, "#")
}

// VolumesSnapshotAction.String

func TestVolumesSnapshotActionString(t *testing.T) {
	cases := []struct {
		action VolumesSnapshotAction
		want   string
	}{
		{VolumesSnapshotCreate, "Create"},
		{VolumesSnapshotRollback, "Rollback"},
		{VolumesSnapshotDelete, "Delete"},
		{VolumesSnapshotUnspecifiedAction, "Unspecified"},
		{VolumesSnapshotAction(99), "Unspecified"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.action.String())
	}
}

// VolumesSnapshotConfig.Key

func TestVolumesSnapshotConfigKey(t *testing.T) {
	cfg := VolumesSnapshotConfig{SnapshotID: "snap-abc-123"}
	assert.Equal(t, "snap-abc-123", cfg.Key())
}

// VolumesSnapshotStatus.Key

func TestVolumesSnapshotStatusKey(t *testing.T) {
	s := VolumesSnapshotStatus{SnapshotID: "snap-xyz-456"}
	assert.Equal(t, "snap-xyz-456", s.Key())
}

// VolumeRefStatus.Key and VolumeKey

func TestVolumeRefStatusKey(t *testing.T) {
	volID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())
	status := VolumeRefStatus{
		VolumeID:               volID,
		GenerationCounter:      1,
		LocalGenerationCounter: 2,
		AppUUID:                appID,
	}
	expected := fmt.Sprintf("%s#3#%s", volID.String(), appID.String())
	assert.Equal(t, expected, status.Key())
}

func TestVolumeRefStatusVolumeKey(t *testing.T) {
	volID := uuid.Must(uuid.NewV4())
	status := VolumeRefStatus{
		VolumeID:          volID,
		GenerationCounter: 5,
	}
	expected := fmt.Sprintf("%s#5", volID.String())
	assert.Equal(t, expected, status.VolumeKey())
}

func TestVolumeRefStatusIsContainer(t *testing.T) {
	status := VolumeRefStatus{ContentFormat: zconfig.Format_CONTAINER}
	assert.True(t, status.IsContainer())

	status.ContentFormat = zconfig.Format_RAW
	assert.False(t, status.IsContainer())
}

// VolumeCreatePending

func TestVolumeCreatePendingKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	pending := VolumeCreatePending{
		VolumeID:          id,
		GenerationCounter: 3,
	}
	expected := fmt.Sprintf("%s#3", id.String())
	assert.Equal(t, expected, pending.Key())
}

func TestVolumeCreatePendingIsContainer(t *testing.T) {
	pending := VolumeCreatePending{ContentFormat: zconfig.Format_CONTAINER}
	assert.True(t, pending.IsContainer())

	pending.ContentFormat = zconfig.Format_RAW
	assert.False(t, pending.IsContainer())
}

func TestVolumeCreatePendingPathName(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	pending := VolumeCreatePending{
		VolumeID:          id,
		GenerationCounter: 1,
		ContentFormat:     zconfig.Format_RAW,
		Encrypted:         false,
	}
	path := pending.PathName()
	assert.Contains(t, path, id.String())
	assert.Contains(t, path, "#1")
	assert.Contains(t, path, VolumeClearDirName)

	pending.Encrypted = true
	encPath := pending.PathName()
	assert.Contains(t, encPath, VolumeEncryptedDirName)
}

// VolumeStatus.PathName

func TestVolumeStatusPathName(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := VolumeStatus{
		VolumeID:          id,
		GenerationCounter: 3,
		ContentFormat:     zconfig.Format_RAW,
		Encrypted:         false,
	}
	path := status.PathName()
	assert.Contains(t, path, id.String())
	assert.Contains(t, path, "#3")
	assert.Contains(t, path, VolumeClearDirName)

	status.Encrypted = true
	encPath := status.PathName()
	assert.Contains(t, encPath, VolumeEncryptedDirName)
}

// VolumeCreatePendingFromVolumeStatus

func TestVolumeCreatePendingFromVolumeStatus(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := VolumeStatus{
		VolumeID:               id,
		GenerationCounter:      2,
		LocalGenerationCounter: 1,
		ContentFormat:          zconfig.Format_CONTAINER,
		Encrypted:              true,
	}
	pending := VolumeCreatePendingFromVolumeStatus(status)
	assert.Equal(t, id, pending.VolumeID)
	assert.Equal(t, int64(2), pending.GenerationCounter)
	assert.Equal(t, int64(1), pending.LocalGenerationCounter)
	assert.Equal(t, zconfig.Format_CONTAINER, pending.ContentFormat)
	assert.True(t, pending.Encrypted)
}

// VolumeRefConfig.VolumeKey

func TestVolumeRefConfigVolumeKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())
	cfg := VolumeRefConfig{
		VolumeID:               id,
		GenerationCounter:      3,
		LocalGenerationCounter: 1,
		AppUUID:                appID,
	}
	key := cfg.VolumeKey()
	expected := fmt.Sprintf("%s#4", id.String()) // 3+1=4
	assert.Equal(t, expected, key)
}

// VolumeConfig.Key / LogKey

func TestVolumeConfigLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := VolumeConfig{VolumeID: id, GenerationCounter: 1}
	expected := fmt.Sprintf("%s#%d", id.String(), 1)
	assert.Equal(t, expected, cfg.Key())
	assert.Contains(t, cfg.LogKey(), expected)
}

// VolumeStatus.Key / LogKey

func TestVolumeStatusLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := VolumeStatus{VolumeID: id, GenerationCounter: 2}
	expected := fmt.Sprintf("%s#%d", id.String(), 2)
	assert.Equal(t, expected, status.Key())
	assert.Contains(t, status.LogKey(), expected)
}

// VolumeMgrStatus.Key / LogKey

func TestVolumeMgrStatusLogKey(t *testing.T) {
	s := VolumeMgrStatus{Name: "persist"}
	assert.Equal(t, "persist", s.Key())
	assert.Contains(t, s.LogKey(), "persist")
}

// VolumeConfig / VolumeStatus / VolumeRefConfig / VolumeRefStatus / VolumeCreatePending / VolumeMgrStatus
// LogCreate / LogModify / LogDelete

func TestVolumeConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	cfg := VolumeConfig{VolumeID: id}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestVolumeStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	s := VolumeStatus{VolumeID: id}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}

func TestVolumeRefConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	volID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())
	cfg := VolumeRefConfig{VolumeID: volID, AppUUID: appID}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestVolumeRefStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	volID := uuid.Must(uuid.NewV4())
	appID := uuid.Must(uuid.NewV4())
	s := VolumeRefStatus{VolumeID: volID, AppUUID: appID}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}

func TestVolumeCreatePendingLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	s := VolumeCreatePending{VolumeID: id}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}

func TestVolumeMgrStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	s := VolumeMgrStatus{Name: "persist"}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}
