/*
 * Copyright (c) 2020. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package types

//SmartData holds SMART details of the device
type SmartData struct {
	SmartCtl        SmartCtl       `json:"smartctl"`
	Device          Device         `json:"device"`
	SmartAttribute  SmartAttribute `json:"ata_smart_attributes"`
	PowerOnTime     PowerOnTime    `json:"power_on_time"`
	PowerCycleCount int64          `json:"power_cycle_count"`
	Temperature     Temperature    `json:"temperature"`
	RawData         string         `json:"raw_data"`
}

//Device holds device details
type Device struct {
	Name     string `json:"name"`
	InfoName string `json:"info_name"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
}

//SmartAttribute holds SMART attributes
type SmartAttribute struct {
	Revision int64   `json:"revision"`
	Table    []Table `json:"table"`
}

//Table schema for each SMART attribute
type Table struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Value      int64  `json:"value"`
	Worst      int64  `json:"worst"`
	Thresh     int64  `json:"thresh"`
	WhenFailed string `json:"when_failed"`
	Flags      Flags  `json:"flags"`
	Raw        Raw    `json:"raw"`
}

//Flags of each SMART attribute
type Flags struct {
	Value         int64  `json:"value"`
	String        string `json:"string"`
	PreFailure    bool   `json:"prefailure"`
	UpdatedOnline bool   `json:"updated_online"`
	Performance   bool   `json:"performance"`
	ErrorRate     bool   `json:"error_rate"`
	EventCount    bool   `json:"event_count"`
	AutoKeep      bool   `json:"auto_keep"`
}

//Raw value of each SMART attribute
type Raw struct {
	Value  int64  `json:"value"`
	String string `json:"string"`
}

//PowerOnTime of the disk
type PowerOnTime struct {
	Hours int64 `json:"hours"`
}

//Temperature of the disk
type Temperature struct {
	Current int64 `json:"current"`
}

//SmartCtl query result.
type SmartCtl struct {
	//ExitStatus non 0 ExitStatus indicates that SMART is not available/disables
	ExitStatus int64 `json:"exit_status"`
}

//NewSmartDataWithDefaults returns 'SmartData' with default values
func NewSmartDataWithDefaults() *SmartData {
	return &SmartData{
		PowerOnTime:     PowerOnTime{Hours: -1},
		PowerCycleCount: -1,
	}
}
