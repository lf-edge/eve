/*
* File Name:	type17_memory_device.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
	"strings"
)

type MemoryDeviceFormFactor byte

func (m MemoryDeviceFormFactor) String() string {
	factors := [...]string{
		"Other",
		"Unknown",
		"SIMM",
		"SIP",
		"Chip",
		"DIP",
		"ZIP",
		"Proprietary Card",
		"DIMM",
		"TSOP",
		"Row of chips",
		"RIMM",
		"SODIMM",
		"SRIMM",
		"FB-DIMM",
	}
	return factors[m-1]
}

func (m MemoryDeviceFormFactor) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

type MemoryDeviceType byte

func (m MemoryDeviceType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"DRAM",
		"EDRAM",
		"VRAM",
		"SRAM",
		"RAM",
		"ROM",
		"FLASH",
		"EEPROM",
		"FEPROM",
		"EPROM",
		"CDRAM",
		"3DRAM",
		"SDRAM",
		"SGRAM",
		"RDRAM",
		"DDR",
		"DDR2",
		"DDR2 FB-DIMM",
		"Reserved 0",
		"Reserved 1",
		"Reserved 2",
		"DDR3",
		"FBD2",
		"DDR4",
		"LPDDR",
		"LPDDR2",
		"LPDDR3",
		"LPDDR4",
	}
	if len(types) <= int(m) {
		return "Unknown"
	}
	return types[m-1]
}

func (m MemoryDeviceType) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

type MemorySizeType uint16
type MemoryDeviceSetType byte

func (s MemoryDeviceSetType) String() string {
	if s == 0x00 {
		return "None"
	} else if s == 0xff {
		return "Unknown"
	}
	return strconv.Itoa(int(s))
}

type MemorySpeedType uint16

func (s MemorySpeedType) String() string {
	if s == 0 {
		return "Unknown"
	} else if s == 0xffff {
		return "Reserved"
	}
	return strconv.Itoa(int(s))
}

type MemoryDeviceTypeDetail uint16

func (m MemoryDeviceTypeDetail) String() string {
	details := [...]string{
		"Reserved",
		"Other",
		"Unknown",
		"Fast-paged",
		"Static column",
		"Pseudo-static",
		"RAMBUS",
		"Synchronous",
		"CMOS",
		"EDO",
		"Window DRAM",
		"Cache DRAM",
		"Non-volatile",
		"Registered (Buffered)",
		"Unbuffered (Unregistered)",
		"LRDIMM",
	}
	res := []string{}
	for i := range details {
		if m>>uint(i)&1 > 0 {
			res = append(res, details[i])
		}
	}
	return strings.Join(res, ", ")
}

func (m MemoryDeviceTypeDetail) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

type MemoryDevice struct {
	infoCommon
	PhysicalMemoryArrayHandle  uint16
	ErrorInformationHandle     uint16
	TotalWidth                 uint16
	DataWidth                  uint16
	Size                       uint64
	FormFactor                 MemoryDeviceFormFactor
	DeviceSet                  MemoryDeviceSetType
	DeviceLocator              string
	BankLocator                string
	Type                       MemoryDeviceType
	TypeDetail                 MemoryDeviceTypeDetail
	Speed                      MemorySpeedType
	Manufacturer               string
	SerialNumber               string
	AssetTag                   string
	PartNumber                 string
	Attributes                 byte
	ConfiguredMemoryClockSpeed uint16
	MinimumVoltage             uint16
	MaximumVoltage             uint16
	ConfiguredVoltage          uint16
}

func (m MemoryDevice) String() string {
	return fmt.Sprintf("Memory Device\n"+
		"\tPhysical Memory Array Handle: %0#X\n"+
		"\tMEMORY ERROR INFORMATION HANDLE: %0#X\n"+
		"\tTotal Width: %dbits\n"+
		"\tData Width: %dbits\n"+
		"\tSize: %d\n"+
		"\tForm Factor: %s\n"+
		"\tDevice Set: %s\n"+
		"\tDevice Locator: %s\n"+
		"\tBank Locator: %s\n"+
		"\tMemory Type: %s\n"+
		"\tType Detail: %s\n"+
		"\tSpeed: %s MHz\n"+
		"\tManufacturer: %s\n"+
		"\tSerial Number: %s\n"+
		"\tAsset Tag: %s\n"+
		"\tPart Number: %s\n"+
		"\tAttributes: %s\n"+
		"\tConfigured Memory Clock Speed: %d\n"+
		"\tMinimum voltage: %d\n"+
		"\tMaximum voltage: %d\n"+
		"\tConfigured voltage: %d ",
		m.PhysicalMemoryArrayHandle,
		m.ErrorInformationHandle,
		m.TotalWidth,
		m.DataWidth,
		m.Size,
		m.FormFactor,
		m.DeviceSet,
		m.DeviceLocator,
		m.BankLocator,
		m.Type,
		m.TypeDetail,
		m.Speed,
		m.Manufacturer,
		m.SerialNumber,
		m.AssetTag,
		m.PartNumber,
		m.Attributes,
		m.ConfiguredMemoryClockSpeed,
		m.MinimumVoltage,
		m.MaximumVoltage,
		m.ConfiguredVoltage,
	)
}

func newMemoryDevice(h dmiHeader) dmiTyper {
	data := h.data
	res := &MemoryDevice{
		PhysicalMemoryArrayHandle:  u16(data[0x04:0x06]),
		ErrorInformationHandle:     u16(data[0x06:0x08]),
		TotalWidth:                 u16(data[0x08:0x0A]),
		DataWidth:                  u16(data[0x0A:0x0C]),
		Size:                       uint64(u16(data[0x0C:0x0e])),
		FormFactor:                 MemoryDeviceFormFactor(data[0x0E]),
		DeviceSet:                  MemoryDeviceSetType(data[0x0F]),
		DeviceLocator:              h.FieldString(int(data[0x10])),
		BankLocator:                h.FieldString(int(data[0x11])),
		Type:                       MemoryDeviceType(data[0x12]),
		TypeDetail:                 MemoryDeviceTypeDetail(u16(data[0x13:0x15])),
		Speed:                      MemorySpeedType(u16(data[0x15:0x17])),
		Manufacturer:               h.FieldString(int(data[0x17])),
		SerialNumber:               h.FieldString(int(data[0x18])),
		AssetTag:                   h.FieldString(int(data[0x19])),
		PartNumber:                 h.FieldString(int(data[0x1A])),
		Attributes:                 data[0x1B],
		ConfiguredMemoryClockSpeed: u16(data[0x20:0x22]),
		MinimumVoltage:             u16(data[0x22:0x24]),
		MaximumVoltage:             u16(data[0x24:0x26]),
		ConfiguredVoltage:          u16(data[0x26:0x28]),
	}
	if res.Size == 0x7fff {
		// Extended size is size in megabytes.  Translate it into bytes
		res.Size = uint64(u32(data[0x1C:0x20])) << 20
	} else if res.Size&0x8000 > 0 {
		// Size is in kilobytes
		res.Size = (res.Size &^ 0x8000) << 10
	} else {
		// Size is in megabytes
		res.Size <<= 20
	}
	MemoryDevices = append(MemoryDevices, res)
	return res
}

var MemoryDevices []*MemoryDevice

func MemoryDeviceInfo() []*MemoryDevice {
	return MemoryDevices
}

func GetMemoryDevice() string {
	var ret string
	for i, v := range MemoryDevices {
		ret += "\nMemoryDevices index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeMemoryDevice, newMemoryDevice)
}
