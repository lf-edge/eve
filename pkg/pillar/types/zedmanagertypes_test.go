// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
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
