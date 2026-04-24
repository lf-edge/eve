// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MetaDataType.String

func TestMetaDataTypeString(t *testing.T) {
	cases := []struct {
		mt   MetaDataType
		want string
	}{
		{MetaDataDrive, "MetaDataDrive"},
		{MetaDataNone, "MetaDataNone"},
		{MetaDataOpenStack, "MetaDataOpenStack"},
		{MetaDataDriveMultipart, "MetaDataDriveMultipart"},
		{MetaDataType(99), fmt.Sprintf("Unknown MetaDataType %d", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.mt.String())
	}
}

// DiskStatus.GetPVCNameFromVolumeKey

func TestDiskStatusGetPVCNameFromVolumeKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := DiskStatus{
		VolumeKey: fmt.Sprintf("%s#3", id.String()),
	}
	name, err := status.GetPVCNameFromVolumeKey()
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%s-pvc-3", id.String()), name)
}

func TestDiskStatusGetPVCNameFromVolumeKeyBadUUID(t *testing.T) {
	status := DiskStatus{VolumeKey: "not-a-uuid#0"}
	_, err := status.GetPVCNameFromVolumeKey()
	assert.Error(t, err)
}

func TestDiskStatusGetPVCNameFromVolumeKeyBadGeneration(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := DiskStatus{VolumeKey: id.String() + "#notanumber"}
	_, err := status.GetPVCNameFromVolumeKey()
	assert.Error(t, err)
}
