/*
* File Name:	type26_voltage_probe.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
*/
package godmi

import (
	"fmt"
)

type VoltageProbeStatus byte

const (
	VoltageProbeStatusOther VoltageProbeStatus = 0x20 + iota
	VoltageProbeStatusUnknown
	VoltageProbeStatusOK
	VoltageProbeStatusNon_critical
	VoltageProbeStatusCritical
	VoltageProbeStatusNon_recoverable
)

func (v VoltageProbeStatus) String() string {
	status := [...]string{
		"Other",
		"Unknown",
		"OK",
		"Non-critical",
		"Critical",
		"Non-recoverable",
	}
	return status[v-6]
}

type VoltageProbeLocation byte

const (
	VoltageProbeLocationOther VoltageProbeLocation = 1 + iota
	VoltageProbeLocationUnknown
	VoltageProbeLocationOK
	VoltageProbeLocationNon_critical
	VoltageProbeLocationCritical
	VoltageProbeLocationNon_recoverable
	VoltageProbeLocationMotherboard
	VoltageProbeLocationMemoryModule
	VoltageProbeLocationProcessorModule
	VoltageProbeLocationPowerUnit
	VoltageProbeLocationAdd_inCard
)

func (v VoltageProbeLocation) String() string {
	locations := [...]string{
		"Other",
		"Unknown",
		"OK",
		"Non-critical",
		"Critical",
		"Non-recoverable",
		"Motherboard",
		"Memory Module",
		"Processor Module",
		"Power Unit",
		"Add-in Card",
	}
	return locations[v-1]
}

type VoltageProbeLocationAndStatus struct {
	Status   VoltageProbeStatus
	Location VoltageProbeLocation
}

func NewVoltageProbeLocationAndStatus(data byte) VoltageProbeLocationAndStatus {
	return VoltageProbeLocationAndStatus{
		Status:   VoltageProbeStatus(data & 0x1F),
		Location: VoltageProbeLocation(data & 0xE0),
	}
}

func (v VoltageProbeLocationAndStatus) String() string {
	return fmt.Sprintf("\n\t\t\t\tStatus: %s\n\t\t\t\tLocation: %s",
		v.Status, v.Location)
}

type VoltageProbe struct {
	infoCommon
	Description       string
	LocationAndStatus VoltageProbeLocationAndStatus
	MaximumValue      uint16
	MinimumValude     uint16
	Resolution        uint16
	Tolerance         uint16
	Accuracy          uint16
	OEMdefined        uint16
	NominalValue      uint16
}

func (v VoltageProbe) String() string {
	return fmt.Sprintf("Voltage Probe\n"+
		"\tDescription: %s\n"+
		"\tLocation And Status: %s\n"+
		"\tMaximum Value: %d\n"+
		"\tMinimum Valude: %d\n"+
		"\tResolution: %d\n"+
		"\tTolerance: %d\n"+
		"\tAccuracy: %d\n"+
		"\tOE Mdefined: %d\n"+
		"\tNominal Value: %d",
		v.Description,
		v.LocationAndStatus,
		v.MaximumValue,
		v.MinimumValude,
		v.Resolution,
		v.Tolerance,
		v.Accuracy,
		v.OEMdefined,
		v.NominalValue)
}
