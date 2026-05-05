// Copyright (c) 2026 Zededa, Inc.
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

	// Valid UUID but non-numeric appNum → strconv.Atoi error branch
	_, _, _, err = DomainnameToUUID("550e8400-e29b-41d4-a716-446655440000.v1.notanumber")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Bad appNum")
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

// Key / LogKey

func TestDomainConfigLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := DomainConfig{UUIDandVersion: UUIDandVersion{UUID: id}}
	assert.Equal(t, id.String(), cfg.Key())
	assert.Contains(t, cfg.LogKey(), id.String())
}

func TestDomainStatusLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	status := DomainStatus{UUIDandVersion: UUIDandVersion{UUID: id}}
	assert.Equal(t, id.String(), status.Key())
	assert.Contains(t, status.LogKey(), id.String())
}

func TestDomainMetricLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	metric := DomainMetric{UUIDandVersion: UUIDandVersion{UUID: id}}
	assert.Equal(t, id.String(), metric.Key())
	assert.Contains(t, metric.LogKey(), id.String())
}

func TestHostMemoryLogKey(t *testing.T) {
	hm := HostMemory{}
	assert.Equal(t, "global", hm.Key())
	assert.Contains(t, hm.LogKey(), "global")
}

// DomainConfig / DomainStatus / DomainMetric / HostMemory LogCreate / LogModify / LogDelete

func TestDomainConfigLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	cfg := DomainConfig{UUIDandVersion: UUIDandVersion{UUID: id}}
	cfg.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	cfg.LogModify(log, cfg)
	cfg.LogDelete(log)
}

func TestDomainStatusLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	s := DomainStatus{UUIDandVersion: UUIDandVersion{UUID: id}}
	s.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	s.LogModify(log, s)
	s.LogDelete(log)
}

func TestDomainMetricLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	id := uuid.Must(uuid.NewV4())
	m := DomainMetric{UUIDandVersion: UUIDandVersion{UUID: id}}
	m.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	m.LogModify(log, m)
	m.LogDelete(log)
}

func TestHostMemoryLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	hm := HostMemory{}
	hm.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	hm.LogModify(log, hm)
	hm.LogDelete(log)
}
