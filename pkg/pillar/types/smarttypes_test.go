// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewSmartDataWithDefaults

func TestNewSmartDataWithDefaults(t *testing.T) {
	d := NewSmartDataWithDefaults()
	require.NotNil(t, d)
	assert.Equal(t, int64(-1), d.PowerOnTime.Hours)
	assert.Equal(t, int64(-1), d.PowerCycleCount)
}

// DiskSmartInfo.GetTemperature

func TestDiskSmartInfoGetTemperature(t *testing.T) {
	dsi := DiskSmartInfo{
		SmartAttrs: []*DAttrTable{
			{ID: SmartAttrIDPowerOnHours, RawValue: 1000},
			{ID: SmartAttrIDTemperatureCelsius, RawValue: 42},
		},
	}
	assert.Equal(t, uint32(42), dsi.GetTemperature())

	// No temperature attr → 0
	dsi2 := DiskSmartInfo{SmartAttrs: []*DAttrTable{
		{ID: SmartAttrIDPowerOnHours, RawValue: 100},
	}}
	assert.Equal(t, uint32(0), dsi2.GetTemperature())
}

// DiskSmartInfo.GetPowerOnTime

func TestDiskSmartInfoGetPowerOnTime(t *testing.T) {
	dsi := DiskSmartInfo{
		SmartAttrs: []*DAttrTable{
			{ID: SmartAttrIDPowerOnHours, RawValue: 5000},
		},
	}
	assert.Equal(t, uint32(5000), dsi.GetPowerOnTime())

	// No attr → 0
	assert.Equal(t, uint32(0), DiskSmartInfo{}.GetPowerOnTime())
}

// DiskSmartInfo.GetPowerCycleCount

func TestDiskSmartInfoGetPowerCycleCount(t *testing.T) {
	dsi := DiskSmartInfo{
		SmartAttrs: []*DAttrTable{
			{ID: SmartAttrIDPowerCycleCount, RawValue: 123},
		},
	}
	assert.Equal(t, uint32(123), dsi.GetPowerCycleCount())

	assert.Equal(t, uint32(0), DiskSmartInfo{}.GetPowerCycleCount())
}

// DiskSmartInfo.GetSmartAttrViaID

func TestDiskSmartInfoGetSmartAttrViaID(t *testing.T) {
	attr := &DAttrTable{ID: SmartAttrIDTemperatureCelsius, RawValue: 37}
	dsi := DiskSmartInfo{SmartAttrs: []*DAttrTable{attr}}

	got := dsi.GetSmartAttrViaID(SmartAttrIDTemperatureCelsius)
	require.NotNil(t, got)
	assert.Equal(t, 37, got.RawValue)

	assert.Nil(t, dsi.GetSmartAttrViaID(999))
}
