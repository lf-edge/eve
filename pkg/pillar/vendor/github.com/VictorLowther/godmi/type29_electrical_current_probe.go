/*
* File Name:	type29_electrical_current_probe.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type ElectricalCurrentProbeStatus byte

const (
	ElectricalCurrentProbeStatusOther ElectricalCurrentProbeStatus = 0x20 + iota
	ElectricalCurrentProbeStatusUnknown
	ElectricalCurrentProbeStatusOK
	ElectricalCurrentProbeStatusNon_critical
	ElectricalCurrentProbeStatusCritical
	ElectricalCurrentProbeStatusNon_recoverable
)

func (e ElectricalCurrentProbeStatus) String() string {
	status := [...]string{
		"Other",
		"Unknown",
		"OK",
		"Non-critical",
		"Critical",
		"Non-recoverable",
	}
	return status[e-0x20]
}

type ElectricalCurrentProbeLocation byte

const (
	ElectricalCurrentProbeLocationOther ElectricalCurrentProbeLocation = 1 + iota
	ElectricalCurrentProbeLocationUnknown
	ElectricalCurrentProbeLocationProcessor
	ElectricalCurrentProbeLocationDisk
	ElectricalCurrentProbeLocationPeripheralBay
	ElectricalCurrentProbeLocationSystemManagementModule
	ElectricalCurrentProbeLocationMotherboard
	ElectricalCurrentProbeLocationMemoryModule
	ElectricalCurrentProbeLocationProcessorModule
	ElectricalCurrentProbeLocationPowerUnit
	ElectricalCurrentProbeLocationAdd_inCard
)

func (e ElectricalCurrentProbeLocation) String() string {
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
	}
	return locations[e-1]
}

type ElectricalCurrentProbeLocationAndStatus struct {
	Status   ElectricalCurrentProbeStatus
	Location ElectricalCurrentProbeLocation
}

func (e ElectricalCurrentProbeLocationAndStatus) String() string {
	return fmt.Sprintf("\n\t\t\t\tStatus: %s\n\t\t\t\tLocation: %s",
		e.Status, e.Location)

}

func NewElectricalCurrentProbeLocationAndStatus(data byte) ElectricalCurrentProbeLocationAndStatus {
	return ElectricalCurrentProbeLocationAndStatus{
		Status:   ElectricalCurrentProbeStatus(data & 0xE0),
		Location: ElectricalCurrentProbeLocation(data & 0x1F),
	}
}

type ElectricalCurrentProbe struct {
	infoCommon
	Description       string
	LocationAndStatus ElectricalCurrentProbeLocationAndStatus
	MaximumValue      uint16
	MinimumValue      uint16
	Resolution        uint16
	Tolerance         uint16
	Accuracy          uint16
	OEMdefined        uint32
	NomimalValue      uint16
}

func (e ElectricalCurrentProbe) String() string {
	return fmt.Sprintf("Electrical Current Probe\n"+
		"\tDescription: %s\n"+
		"\tLocation And Status: %s\n"+
		"\tMaximum Value: %d\n"+
		"\tMinimum Value: %d\n"+
		"\tResolution: %d\n"+
		"\tTolerance: %d\n"+
		"\tAccuracy: %d\n"+
		"\tOE Mdefined: %d\n"+
		"\tNomimal Value: %d\n",
		e.Description,
		e.LocationAndStatus,
		e.MaximumValue,
		e.MinimumValue,
		e.Resolution,
		e.Tolerance,
		e.Accuracy,
		e.OEMdefined,
		e.NomimalValue)
}

