// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	zconfig "github.com/lf-edge/eve-api/go/config"
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

// DomainConfig.IsOCIContainer

func TestDomainConfigIsOCIContainer(t *testing.T) {
	// No disks → false
	assert.False(t, DomainConfig{}.IsOCIContainer())

	// First disk is CONTAINER → true
	cfg := DomainConfig{
		DiskConfigList: []DiskConfig{
			{Format: zconfig.Format_CONTAINER},
		},
	}
	assert.True(t, cfg.IsOCIContainer())

	// First disk is not CONTAINER → false
	cfg.DiskConfigList[0].Format = zconfig.Format_RAW
	assert.False(t, cfg.IsOCIContainer())
}

// DomainConfig.GetTaskName and DomainnameToUUID

func TestDomainConfigGetTaskNameRoundtrip(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := DomainConfig{
		UUIDandVersion: UUIDandVersion{UUID: id, Version: "2"},
		AppNum:         7,
	}
	name := cfg.GetTaskName()
	assert.Equal(t, fmt.Sprintf("%s.2.7", id.String()), name)

	gotID, gotVer, gotAppNum, err := DomainnameToUUID(name)
	require.NoError(t, err)
	assert.Equal(t, id, gotID)
	assert.Equal(t, "2", gotVer)
	assert.Equal(t, 7, gotAppNum)
}

func TestDomainnameToUUIDDomain0(t *testing.T) {
	id, ver, num, err := DomainnameToUUID("Domain-0")
	require.NoError(t, err)
	assert.Equal(t, uuid.UUID{}, id)
	assert.Equal(t, "", ver)
	assert.Equal(t, 0, num)
}

func TestDomainnameToUUIDErrors(t *testing.T) {
	_, _, _, err := DomainnameToUUID("bad.format")
	assert.Error(t, err)

	_, _, _, err = DomainnameToUUID("not-uuid.v.0")
	assert.Error(t, err)
}

// DomainConfig.VirtualizationModeOrDefault

func TestDomainConfigVirtualizationModeOrDefault(t *testing.T) {
	cfg := DomainConfig{VmConfig: VmConfig{VirtualizationMode: HVM}}
	assert.Equal(t, HVM, cfg.VirtualizationModeOrDefault())

	// Unknown mode → PV
	cfg.VmConfig.VirtualizationMode = VmMode(99)
	assert.Equal(t, PV, cfg.VirtualizationModeOrDefault())
}

// DomainStatus.VifInfoByVif

func TestDomainStatusVifInfoByVif(t *testing.T) {
	status := DomainStatus{
		VifList: []VifInfo{
			{VifConfig: VifConfig{Vif: "vif1"}},
			{VifConfig: VifConfig{Vif: "vif2"}},
		},
	}
	info := status.VifInfoByVif("vif1")
	require.NotNil(t, info)
	assert.Equal(t, "vif1", info.Vif)

	assert.Nil(t, status.VifInfoByVif("missing"))
}

// DomainStatus.Pending

func TestDomainStatusPending(t *testing.T) {
	assert.False(t, DomainStatus{}.Pending())

	assert.True(t, DomainStatus{PendingAdd: true}.Pending())
	assert.True(t, DomainStatus{PendingModify: true}.Pending())
	assert.True(t, DomainStatus{PendingDelete: true}.Pending())
}
