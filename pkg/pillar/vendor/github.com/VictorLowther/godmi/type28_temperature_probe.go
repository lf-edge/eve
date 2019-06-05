/*
* File Name:	type28_temperature_probe.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
*/
package godmi

import (
	"fmt"
)

type TemperatureProbeStatus byte

const (
	TemperatureProbeStatusOther TemperatureProbeStatus = 0x20 + iota
	TemperatureProbeStatusUnknown
	TemperatureProbeStatusOK
	TemperatureProbeStatusNon_critical
	TemperatureProbeStatusCritical
	TemperatureProbeStatusNon_recoverable
)

func (t TemperatureProbeStatus) String() string {
	status := [...]string{
		"Other",
		"Unknown",
		"OK",
		"Non-critical",
		"Critical",
		"Non-recoverable",
	}
	return status[t-0x20]
}

type TemperatureProbeLocation byte

const (
	TemperatureProbeLocationOther TemperatureProbeStatus = 1 + iota
	TemperatureProbeLocationUnknown
	TemperatureProbeLocationProcessor
	TemperatureProbeLocationDisk
	TemperatureProbeLocationPeripheralBay
	TemperatureProbeLocationSystemManagementModule
	TemperatureProbeLocationMotherboard
	TemperatureProbeLocationMemoryModule
	TemperatureProbeLocationProcessorModule
	TemperatureProbeLocationPowerUnit
	TemperatureProbeLocationAdd_inCard
	TemperatureProbeLocationFrontPanelBoard
	TemperatureProbeLocationBackPanelBoard
	TemperatureProbeLocationPowerSystemBoard
	TemperatureProbeLocationDriveBackPlane
)

func (t TemperatureProbeLocation) String() string {
	locations := [...]string{
		"Other",
		"Unknown",
		"Processor",
		"Disk",
		"Peripheral Bay",
		"System Management Module",
		"Motherboard",
		"Memory Module",
		"Processor Module",
		"Power Unit",
		"Add-in Card",
		"Front Panel Board",
		"Back Panel Board",
		"Power System Board",
		"Drive Back Plane",
	}
	return locations[t-1]
}

type TemperatureProbeLocationAndStatus struct {
	Status   TemperatureProbeStatus
	Location TemperatureProbeLocation
}

func (t TemperatureProbeLocationAndStatus) String() string {
	return fmt.Sprintf("\n\t\t\t\tStatus: %s\n\t\t\t\tLocation: %s",
		t.Status, t.Location)
}

func NewTemperatureProbeLocationAndStatus(data byte) TemperatureProbeLocationAndStatus {
	return TemperatureProbeLocationAndStatus{
		Status:   TemperatureProbeStatus(data & 0xE0),
		Location: TemperatureProbeLocation(data & 0x1F),
	}
}

type TemperatureProbe struct {
	infoCommon
	Description       string
	LocationAndStatus TemperatureProbeLocationAndStatus
	MaximumValue      uint16
	MinimumValue      uint16
	Resolution        uint16
	Tolerance         uint16
	Accuracy          uint16
	OEMdefined        uint32
	NominalValue      uint16
}

func (t TemperatureProbe) String() string {
	return fmt.Sprintf("Temperature Probe\n"+
		"\tDescription: %s\n"+
		"\tLocation And Status: %s\n"+
		"\tMaximum Value: %d\n"+
		"\tMinimum Value: %d\n"+
		"\tResolution: %d\n"+
		"\tTolerance: %d\n"+
		"\tAccuracy: %d\n"+
		"\tOE Mdefined: %d\n"+
		"\tNominal Value: %d",
		t.Description,
		t.LocationAndStatus,
		t.MaximumValue,
		t.MinimumValue,
		t.Resolution,
		t.Tolerance,
		t.Accuracy,
		t.OEMdefined,
		t.NominalValue)
}
