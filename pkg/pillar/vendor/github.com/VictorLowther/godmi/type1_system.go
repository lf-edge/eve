/*
* File Name:	type1_system.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-18 22:52:15
 */

package godmi

import (
	"fmt"
	"strconv"
)

type SystemInformationWakeUpType byte

var systemInformationWakeupType = []string{
	"Reserved", /* 0x00 */
	"Other",
	"Unknown",
	"APM Timer",
	"Modem Ring",
	"LAN Remote",
	"Power Switch",
	"PCI PME#",
	"AC Power Restored", /* 0x08 */
}

func (w SystemInformationWakeUpType) String() string {
	return systemInformationWakeupType[w]
}

func (w SystemInformationWakeUpType) MarshalText() ([]byte, error) {
	return []byte(w.String()), nil
}

type SystemInformation struct {
	infoCommon
	Manufacturer string
	ProductName  string
	Version      string
	SerialNumber string
	UUID         string
	WakeUpType   SystemInformationWakeUpType
	SKUNumber    string
	Family       string
}

func (s SystemInformation) String() string {
	return fmt.Sprintf("System Information\n"+
		"\tManufacturer: %s\n"+
		"\tProduct Name: %s\n"+
		"\tVersion: %s\n"+
		"\tSerial Number: %s\n"+
		"\tUUID: %s\n"+
		"\tWake-up Type: %s\n"+
		"\tSKU Number: %s\n"+
		"\tFamily: %s",
		s.Manufacturer,
		s.ProductName,
		s.Version,
		s.SerialNumber,
		s.UUID,
		s.WakeUpType,
		s.SKUNumber,
		s.Family)
}

var SystemInformations []*SystemInformation

func newSystemInformation(h dmiHeader) dmiTyper {
	data := h.data
	version := h.FieldString(int(data[0x06]))
	si := &SystemInformation{
		Manufacturer: h.FieldString(int(data[0x04])),
		ProductName:  h.FieldString(int(data[0x05])),
		Version:      version,
		SerialNumber: h.FieldString(int(data[0x07])),
		UUID:         uuid(data[0x08:0x18], version),
		WakeUpType:   SystemInformationWakeUpType(data[0x18]),
		SKUNumber:    h.FieldString(int(data[0x19])),
		Family:       h.FieldString(int(data[0x1A])),
	}
	SystemInformations = append(SystemInformations, si)
	return si
}

func GetSystemInformation() string {
	var ret string
	for i, v := range SystemInformations {
		ret += "SystemInfomation index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeSystem, newSystemInformation)
}
