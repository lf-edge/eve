/*
 * Copyright (c) 2022. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package types

// DeviceSmartInfo holds SMART details of the device
type DeviceSmartInfo struct {
	PowerOnTime     PowerOnTime `json:"power_on_time"`
	PowerCycleCount int64       `json:"power_cycle_count"`
}

// PowerOnTime of the disk
type PowerOnTime struct {
	Hours int64 `json:"hours"`
}

// NewSmartDataWithDefaults returns 'SmartData' with default values
func NewSmartDataWithDefaults() *DeviceSmartInfo {
	return &DeviceSmartInfo{
		PowerOnTime:     PowerOnTime{Hours: -1},
		PowerCycleCount: -1,
	}
}

// DiskType defines disk types
type DiskType int

// CollectingStatus specifies the state of the error collector
type CollectingStatus int

const (
	// SmartDiskTypeUnknown - Unknown type disk
	SmartDiskTypeUnknown DiskType = iota
	// SmartDiskTypeScsi - SCSI disk
	SmartDiskTypeScsi
	// SmartDiskTypeSata - SATA disk
	SmartDiskTypeSata
	// SmartDiskTypeNvme - NVME disk
	SmartDiskTypeNvme
)

const (
	// SmartCollectingStatusSuccess - status of successful data collection
	SmartCollectingStatusSuccess CollectingStatus = iota
	// SmartCollectingStatusError - error status
	SmartCollectingStatusError
)

// The attributes we want to collect.
// Description: https://en.wikipedia.org/wiki/S.M.A.R.T.
const (
	// SmartAttrIDPowerCycleCount - this attribute indicates the count of full hard disk power on/off cycles
	SmartAttrIDPowerCycleCount int = 12
	// SmartAttrIDPowerOnHours - count of hours in power-on state.
	SmartAttrIDPowerOnHours int = 9
	// SmartAttrIDRealLocatedSectorCt - count of reallocated sectors. The higher the attribute value, the more sectors were reallocated
	SmartAttrIDRealLocatedSectorCt int = 5
	// SmartAttrIDCurrentPendingSectorCt - count of "unstable" sectors (waiting to be remapped, because of unrecoverable read errors)
	SmartAttrIDCurrentPendingSectorCt int = 197
	// SmartAttrIDTemperatureCelsius - indicates the device temperature, if the appropriate sensor is fitted.
	SmartAttrIDTemperatureCelsius int = 194
	// SmartAttrIDRealLocatedEventCount - count of remap operations. Shows the total count of attempts.
	SmartAttrIDRealLocatedEventCount int = 196
)

// DAttrTable have smart attr received via API
type DAttrTable struct {
	ID       int
	Value    int
	Worst    int
	Flags    int
	RawValue int
}

// DiskSmartInfo have smart data received via API
type DiskSmartInfo struct {
	DiskName         string   // /dev/sda
	DiskType         DiskType //SATA, SCSI, NVME    enum
	ModelNumber      string   // Intel ...
	SerialNumber     string
	Wwn              uint64
	SmartAttrs       []*DAttrTable // Temperature, PowerOnTime, PowerCycleCount ...
	TimeUpdate       uint64        // Date last collect info in seconds
	Errors           error         // errors in data collection
	CollectingStatus CollectingStatus
}

// DisksInformation main struct for SMART
type DisksInformation struct {
	Disks []*DiskSmartInfo
}

// GetTemperature returns the disk temperature in degrees Celsius
func (dsi DiskSmartInfo) GetTemperature() uint32 {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == SmartAttrIDTemperatureCelsius {
			return uint32(attr.RawValue)
		}
	}
	return 0
}

// GetPowerOnTime returns count of hours in power-on state
func (dsi DiskSmartInfo) GetPowerOnTime() uint32 {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == SmartAttrIDPowerOnHours {
			return uint32(attr.RawValue)
		}
	}
	return 0
}

// GetPowerCycleCount returns  count of full hard disk power on/off cycles.
func (dsi DiskSmartInfo) GetPowerCycleCount() uint32 {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == SmartAttrIDPowerCycleCount {
			return uint32(attr.RawValue)
		}
	}
	return 0
}

// GetSmartAttrViaID takes an attribute ID (SmartAttrID...) as input,
// returns the properties of this attribute (struct DAttrTable).
func (dsi DiskSmartInfo) GetSmartAttrViaID(id int) *DAttrTable {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == id {
			return attr
		}
	}
	return nil
}
