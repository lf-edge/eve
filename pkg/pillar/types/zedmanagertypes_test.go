// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

// SnapshotType.String

func TestSnapshotTypeString(t *testing.T) {
	cases := []struct {
		st   SnapshotType
		want string
	}{
		{SnapshotTypeUnspecified, "SnapshotTypeUnspecified"},
		{SnapshotTypeAppUpdate, "SnapshotTypeAppUpdate"},
		{SnapshotTypeImmediate, "SnapshotTypeImmediate"},
		{SnapshotType(99), fmt.Sprintf("Unknown SnapshotType %d", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.st.String())
	}
}

// SnapshotType.ConvertToInfoSnapshotType

func TestSnapshotTypeConvertToInfoSnapshotType(t *testing.T) {
	assert.Equal(t, info.SnapshotType_SNAPSHOT_TYPE_APP_UPDATE,
		SnapshotTypeAppUpdate.ConvertToInfoSnapshotType())
	assert.Equal(t, info.SnapshotType_SNAPSHOT_TYPE_IMMEDIATE,
		SnapshotTypeImmediate.ConvertToInfoSnapshotType())
	assert.Equal(t, info.SnapshotType_SNAPSHOT_TYPE_UNSPECIFIED,
		SnapshotTypeUnspecified.ConvertToInfoSnapshotType())
	// Unknown maps to unspecified
	assert.Equal(t, info.SnapshotType_SNAPSHOT_TYPE_UNSPECIFIED,
		SnapshotType(99).ConvertToInfoSnapshotType())
}

// GetSnapshotDir and related helpers

func TestGetSnapshotDir(t *testing.T) {
	dir := GetSnapshotDir("snap-123")
	assert.Equal(t, filepath.Join(SnapshotsDirname, "snap-123"), dir)
}

func TestGetVolumesSnapshotStatusFile(t *testing.T) {
	f := GetVolumesSnapshotStatusFile("snap-123")
	expected := filepath.Join(SnapshotsDirname, "snap-123", SnapshotVolumesSnapshotStatusFilename)
	assert.Equal(t, expected, f)
}

func TestGetSnapshotInstanceStatusFile(t *testing.T) {
	f := GetSnapshotInstanceStatusFile("snap-456")
	expected := filepath.Join(SnapshotsDirname, "snap-456", SnapshotInstanceStatusFilename)
	assert.Equal(t, expected, f)
}

func TestGetSnapshotAppInstanceConfigFile(t *testing.T) {
	f := GetSnapshotAppInstanceConfigFile("snap-789")
	expected := filepath.Join(SnapshotsDirname, "snap-789", SnapshotAppInstanceConfigFilename)
	assert.Equal(t, expected, f)
}

// RoundupToKB

func TestRoundupToKB(t *testing.T) {
	assert.Equal(t, uint64(0), RoundupToKB(0))
	assert.Equal(t, uint64(1), RoundupToKB(1))
	assert.Equal(t, uint64(1), RoundupToKB(1023))
	assert.Equal(t, uint64(1), RoundupToKB(1024))
	assert.Equal(t, uint64(2), RoundupToKB(1025))
}

// AppInstanceStatus.GetAppInterfaceList

func TestGetAppInterfaceList(t *testing.T) {
	status := AppInstanceStatus{
		AppNetAdapters: []AppNetAdapterStatus{
			{VifInfo: VifInfo{VifUsed: "vif0"}},
			{VifInfo: VifInfo{VifUsed: ""}},
			{VifInfo: VifInfo{VifUsed: "vif2"}},
		},
	}
	list := status.GetAppInterfaceList()
	assert.Equal(t, []string{"vif0", "vif2"}, list)

	// Empty adapters → nil slice
	empty := AppInstanceStatus{}
	assert.Nil(t, empty.GetAppInterfaceList())
}

// AppInstanceConfig / AppInstanceStatus / AppInstanceSummary / AppAndImageToHash Key / LogKey

func TestAppInstanceConfigLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := AppInstanceConfig{UUIDandVersion: UUIDandVersion{UUID: id}}
	assert.Equal(t, id.String(), cfg.Key())
	assert.Contains(t, cfg.LogKey(), id.String())
}

func TestAppInstanceStatusLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := AppInstanceStatus{UUIDandVersion: UUIDandVersion{UUID: id}}
	assert.Equal(t, id.String(), status.Key())
	assert.Contains(t, status.LogKey(), id.String())
}

func TestAppInstanceSummaryKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	s := AppInstanceSummary{UUIDandVersion: UUIDandVersion{UUID: id}}
	assert.Equal(t, id.String(), s.Key())
}

func TestAppAndImageToHashLogKey(t *testing.T) {
	appID := uuid.Must(uuid.NewV4())
	imgID := uuid.Must(uuid.NewV4())
	aih := AppAndImageToHash{AppUUID: appID, ImageID: imgID}
	key := aih.Key()
	assert.Contains(t, key, appID.String())
	assert.Contains(t, aih.LogKey(), key)

	// With PurgeCounter
	aih.PurgeCounter = 3
	assert.Contains(t, aih.Key(), "3")
}
