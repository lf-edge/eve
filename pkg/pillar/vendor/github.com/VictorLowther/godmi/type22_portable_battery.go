/*
* File Name:	type22_portable_battery.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type PortableBatteryDeviceChemistry byte

func (p PortableBatteryDeviceChemistry) String() string {
	chems := [...]string{
		"Other",
		"Unknown(see SBDS Device Chemistry)",
		"Lead Acid",
		"Nickel Cadmium",
		"Nickel metal hydride",
		"Lithium-ion",
		"Zinc air",
		"Lithium Polymer",
	}
	return chems[p-1]
}

type SBDSManufactureDateType uint16

func (s SBDSManufactureDateType) String() string {
	// Bits 4:0 Date
	date := s & 0x0010
	// Bits 8:5 Month
	month := s & 0x01E0
	// Bits 15:9 year
	year := s&0xFE00 + 1980

	if year == 1980 {
		return ""
	}

	var ret string
	ret += " year: " + strconv.Itoa(int(year))
	ret += " month: " + strconv.Itoa(int(month))
	ret += " date: " + strconv.Itoa(int(date))
	return ret
}

type DesignCapacityType uint16

func (d DesignCapacityType) String() string {
	if d == 0 {
		return "Unknown"
	}
	return strconv.Itoa(int(d))
}

type DesignVoltageType uint32

func (d DesignVoltageType) String() string {
	if d == 0 {
		return "Unknown"
	}
	return strconv.Itoa(int(d))
}

type MaximumErrorInBatteryDataType byte

func (m MaximumErrorInBatteryDataType) String() string {
	if m == 0xFF {
		return "Unknown"
	}
	return strconv.Itoa(int(m))
}

type PortableBattery struct {
	infoCommon
	Location                  string
	Manufacturer              string
	ManufacturerDate          string
	SerialNumber              string
	DeviceName                string
	DeviceChemistry           PortableBatteryDeviceChemistry
	DesignCapacity            DesignCapacityType
	DesignVoltage             DesignVoltageType
	SBDSVersionNumber         string
	MaximumErrorInBatteryData MaximumErrorInBatteryDataType
	SBDSSerialNumber          uint16
	SBDSManufactureDate       SBDSManufactureDateType
	SBDSDeviceChemistry       string
	DesignCapacityMultiplier  byte
	OEMSepecific              uint32
}

func (p PortableBattery) String() string {
	return fmt.Sprintf("Portable Battery\n"+
		"\tLocation: %s\n"+
		"\tManufacturer: %s\n"+
		"\tManufacturer Date: %s\n"+
		"\tSerial Number: %s\n"+
		"\tDevice Name: %s\n"+
		"\tDevice Chemistry: %s\n"+
		"\tDesign Capacity: %s\n"+
		"\tDesign Voltage: %s\n"+
		"\tSBDS Version Number: %s\n"+
		"\tMaximum Error in Battery Data: %s\n"+
		"\tSBDS Serial Number: %d\n"+
		"\tSBDS Manufacturer Date: %s\n"+
		"\tSBDS Device Chemistry: %s\n"+
		"\tDesign Capacity Multiplier: %d\n"+
		"\tOEM-specific: %d",
		p.Location,
		p.Manufacturer,
		p.ManufacturerDate,
		p.SerialNumber,
		p.DeviceName,
		p.DeviceChemistry,
		p.DesignCapacity,
		p.DesignVoltage,
		p.SBDSVersionNumber,
		p.MaximumErrorInBatteryData,
		p.SBDSSerialNumber,
		p.SBDSManufactureDate,
		p.SBDSDeviceChemistry,
		p.DesignCapacityMultiplier,
		p.OEMSepecific,
	)
}

func newPortableBattery(h dmiHeader) dmiTyper {
	data := h.data
	pi := &PortableBattery{
		Location:                  h.FieldString(int(data[0x04])),
		Manufacturer:              h.FieldString(int(data[0x05])),
		ManufacturerDate:          h.FieldString(int(data[0x06])),
		SerialNumber:              h.FieldString(int(data[0x07])),
		DeviceName:                h.FieldString(int(data[0x08])),
		DeviceChemistry:           PortableBatteryDeviceChemistry(data[0x09]),
		DesignCapacity:            DesignCapacityType(u16(data[0x0A:0x0C])),
		DesignVoltage:             DesignVoltageType(u16(data[0x0C:0x0E])),
		SBDSVersionNumber:         h.FieldString(int(data[0x0E])),
		MaximumErrorInBatteryData: MaximumErrorInBatteryDataType(data[0x0F]),
		SBDSSerialNumber:          u16(data[0x10:0x12]),
		SBDSManufactureDate:       SBDSManufactureDateType(u16(data[0x12:0x14])),
		SBDSDeviceChemistry:       h.FieldString(int(data[0x14])),
		DesignCapacityMultiplier:  data[0x15],
		OEMSepecific:              u32(data[0x16:0x1A]),
	}
	PortableBatterys = append(PortableBatterys, pi)
	return pi
}

var PortableBatterys []*PortableBattery

func GetPortableBattery() string {
	var ret string
	for i, v := range PortableBatterys {
		ret += "\nPortable Battterys information index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypePortableBattery, newPortableBattery)
}
