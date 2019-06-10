/*
* File Name:	type27_cooling_device.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
)

type CoolingDeviceStatus byte

const (
	CoolingDeviceStatusOther CoolingDeviceStatus = 0x20 + iota
	CoolingDeviceStatusUnknown
	CoolingDeviceStatusOK
	CoolingDeviceStatusNon_critical
	CoolingDeviceStatusCritical
	CoolingDeviceStatusNon_recoverable
)

func (c CoolingDeviceStatus) String() string {
	status := [...]string{
		"Other",
		"Unknown",
		"OK",
		"Non-critical",
		"Critical",
		"Non-recoverable",
	}
	return status[c-0x20]
}

type CoolingDeviceType byte

const (
	CoolingDeviceTypeOther CoolingDeviceType = 1 + iota
	CoolingDeviceTypeUnknown
	CoolingDeviceTypeFan
	CoolingDeviceTypeCentrifugalBlower
	CoolingDeviceTypeChipFan
	CoolingDeviceTypeCabinetFan
	CoolingDeviceTypePowerSupplyFan
	CoolingDeviceTypeHeatPipe
	CoolingDeviceTypeIntegratedRefrigeration
	CoolingDeviceTypeActiveCooling
	CoolingDeviceTypePassiveCooling
)

func (c CoolingDeviceType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"Fan",
		"Centrifugal Blower",
		"Chip Fan",
		"Cabinet Fan",
		"Power Supply Fan",
		"Heat Pipe",
		"Integrated Refrigeration",
		"Active Cooling",
		"Passive Cooling",
	}
	return types[c-1]
}

type CoolingDeviceTypeAndStatus struct {
	Status CoolingDeviceStatus
	Type   CoolingDeviceType
}

func NewCoolingDeviceTypeAndStatus(data byte) CoolingDeviceTypeAndStatus {
	return CoolingDeviceTypeAndStatus{
		Status: CoolingDeviceStatus(data & 0xE0),
		Type:   CoolingDeviceType(data & 0x1F),
	}
}

type CoolingDevice struct {
	infoCommon
	TemperatureProbeHandle uint16
	DeviceTypeAndStatus    CoolingDeviceTypeAndStatus
	CoolingUintGroup       byte
	OEMdefined             uint32
	NominalSpeed           uint16
	Description            string
}

func (c CoolingDevice) String() string {
	s := fmt.Sprintf("Cooling Device\n"+
		"\tTemperature Probe Handle: %d\n"+
		"\tDevice Type And Status: %s\n"+
		"\tCooling Uint Group: %d\n"+
		"\tOE Mdefined: %d\n",
		c.TemperatureProbeHandle,
		c.DeviceTypeAndStatus,
		c.CoolingUintGroup,
		c.OEMdefined,
	)
	if c.length > 0x0C {
		s += fmt.Sprintf("\tNominal Speed: %d\n", c.NominalSpeed)
	}
	if c.length > 0x0F {
		s += fmt.Sprintf("\tDescription: %s\n", c.Description)
	}
	return s
}
