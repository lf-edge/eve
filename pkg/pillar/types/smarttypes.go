/*
 * Copyright (c) 2022. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package types

//DeviceSmartInfo holds SMART details of the device
type DeviceSmartInfo struct {
	Smartctl           cmdSmartctl     `json:"smartctl"`
	Device             device          `json:"device"`
	ModelName          string          `json:"model_name"`
	SerialNumber       string          `json:"serial_number"`
	Wwn                smWWN           `json:"wwn"`
	AtaSmartAttributes SmartAttributes `json:"ata_smart_attributes"`
	Temperature        Temperature     `json:"temperature"`
	PowerOnTime        PowerOnTime     `json:"power_on_time"`
	PowerCycleCount    int64           `json:"power_cycle_count"`
}

//DisksList holds list with disks
type DisksList struct {
	Smartctl cmdSmartctl `json:"smartctl"`
	Devices  []device    `json:"devices"`
}

type errMessages struct {
	String   string `json:"string"`
	Severity string `json:"severity"`
}

//cmdSmartctl query result.
type cmdSmartctl struct {
	Argv       []string      `json:"argv"`
	Messages   []errMessages `json:"messages"`
	ExitStatus int           `json:"exit_status"`
}

//device holds device details
type device struct {
	Name     string `json:"name"`
	InfoName string `json:"info_name"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
}

type smWWN struct {
	Naa int   `json:"naa"`
	Oui int   `json:"oui"`
	ID  int64 `json:"id"`
}

type smFlags struct {
	Value         int    `json:"value"`
	String        string `json:"string"`
	Prefailure    bool   `json:"prefailure"`
	UpdatedOnline bool   `json:"updated_online"`
	Performance   bool   `json:"performance"`
	ErrorRate     bool   `json:"error_rate"`
	EventCount    bool   `json:"event_count"`
	AutoKeep      bool   `json:"auto_keep"`
}

type smRaw struct {
	Value  int    `json:"value"`
	String string `json:"string"`
}

type smAttrTable struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	Value      int     `json:"value"`
	Worst      int     `json:"worst"`
	Thresh     int     `json:"thresh"`
	WhenFailed string  `json:"when_failed"`
	Flags      smFlags `json:"flags"`
	Raw        smRaw   `json:"raw"`
}

//SmartAttributes holds SMART attributes
type SmartAttributes struct {
	Revision int           `json:"revision"`
	Table    []smAttrTable `json:"table"`
}

//PowerOnTime of the disk
type PowerOnTime struct {
	Hours int64 `json:"hours"`
}

//Temperature of the disk
type Temperature struct {
	Current int64 `json:"current"`
}

//NewSmartDataWithDefaults returns 'SmartData' with default values
func NewSmartDataWithDefaults() *DeviceSmartInfo {
	return &DeviceSmartInfo{
		PowerOnTime:     PowerOnTime{Hours: -1},
		PowerCycleCount: -1,
	}
}

type DiskType int
type CollectingStatus int

const (
	SMART_SCSI_DISK_TYPE DiskType = iota
	SMART_SATA_DISK_TYPE
	SMART_NVME_DISK_TYPE
)

const (
	SMART_COLLECTING_STATUS_SUCCESS CollectingStatus = iota
	SMART_COLLECTING_STATUS_ERROR
)

const (
	// The attributes we want to collect.
	// Description: https://en.wikipedia.org/wiki/S.M.A.R.T.
	SMART_ATTR_ID_POWER_CYCLE_COUNT         int = 12
	SMART_ATTR_ID_POWER_ON_HOURS            int = 9
	SMART_ATTR_ID_REAL_LOCATED_SECTOR_CT    int = 5
	SMART_ATTR_ID_CURRENT_PENDING_SECTOR_CT int = 197
	SMART_ATTR_ID_TEMPERATURE_CELSIUS       int = 194
	SMART_ATTR_ID_REAL_LOCATED_EVENT_COUNT  int = 196
)

//DAttrTable have smart attr received via API
type DAttrTable struct {
	ID       int
	Value    int
	Worst    int
	Flags    int
	RawValue int
}

//DiskSmartInfo have smart data received via API
type DiskSmartInfo struct {
	DiskName         string   		// /dev/sda
	DiskType         DiskType 		//SATA, SCSI, NVME    enum
	ModelNumber      string   		// Intel ...
	SerialNumber     string
	Wwn              uint64
	SmartAttrs       []*DAttrTable 	// Temperature, PowerOnTime, PowerCycleCount ...
	TimeUpdate       uint64        	// Date last collect info in seconds
	Errors           error         	// errors in data collection
	CollectingStatus CollectingStatus
}

// DisksInformation main struct for SMART
type DisksInformation struct {
	Disks []*DiskSmartInfo
}

// GetTemperature returns the disk temperature in degrees Celsius
func (dsi DiskSmartInfo) GetTemperature() uint32 {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == SMART_ATTR_ID_TEMPERATURE_CELSIUS {
			return uint32(attr.RawValue)
		}
	}
	return 0
}

// GetPowerOnTime returns count of hours in power-on state
func (dsi DiskSmartInfo) GetPowerOnTime() uint32 {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == SMART_ATTR_ID_POWER_ON_HOURS {
			return uint32(attr.RawValue)
		}
	}
	return 0
}

// PowerCycleCount returns  count of full hard disk power on/off cycles.
func (dsi DiskSmartInfo) GetPowerCycleCount() uint32 {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == SMART_ATTR_ID_POWER_CYCLE_COUNT {
			return uint32(attr.RawValue)
		}
	}
	return 0
}

// GetSmartAttrViaID takes an attribute ID as input,
// returns the properties of this attribute.
func (dsi DiskSmartInfo) GetSmartAttrViaID(id int) *DAttrTable {
	for _, attr := range dsi.SmartAttrs {
		if attr.ID == id {
			return attr
		}
	}
	return nil
}
