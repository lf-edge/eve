/*
* File Name:	type34_management_device.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type ManagementDeviceType byte

const (
	ManagementDeviceTypeOther ManagementDeviceType = 1 + iota
	ManagementDeviceTypeUnknown
	ManagementDeviceTypeNationalSemiconductorLM75
	ManagementDeviceTypeNationalSemiconductorLM78
	ManagementDeviceTypeNationalSemiconductorLM79
	ManagementDeviceTypeNationalSemiconductorLM80
	ManagementDeviceTypeNationalSemiconductorLM81
	ManagementDeviceTypeAnalogDevicesADM9240
	ManagementDeviceTypeDallasSemiconductorDS1780
	ManagementDeviceTypeMaxim1617
	ManagementDeviceTypeGenesysGL518SM
	ManagementDeviceTypeWinbondW83781D
	ManagementDeviceTypeHoltekHT82H791
)

func (m ManagementDeviceType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"National Semiconductor LM75",
		"National Semiconductor LM78",
		"National Semiconductor LM79",
		"National Semiconductor LM80",
		"National Semiconductor LM81",
		"Analog Devices ADM9240",
		"Dallas Semiconductor DS1780",
		"Maxim 1617",
		"Genesys GL518SM",
		"Winbond W83781D",
		"Holtek HT82H791",
	}
	return types[m-1]
}

type ManagementDeviceAddressType byte

const (
	ManagementDeviceAddressTypeOther ManagementDeviceAddressType = 1 + iota
	ManagementDeviceAddressTypeUnknown
	ManagementDeviceAddressTypeIOPort
	ManagementDeviceAddressTypeMemory
	ManagementDeviceAddressTypeSMBus
)

func (m ManagementDeviceAddressType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"I/O Port",
		"Memory",
		"SM Bus",
	}
	return types[m-1]
}

type ManagementDevice struct {
	infoCommon
	Description string
	Type        ManagementDeviceType
	Address     uint32
	AddressType ManagementDeviceAddressType
}

func (m ManagementDevice) String() string {
	return fmt.Sprintf("Management Device\n"+
		"\tDescription: %s\n"+
		"\tType: %s\n"+
		"\tAddress: %d\n"+
		"\tAddress Type: %s",
		m.Description,
		m.Type,
		m.Address,
		m.AddressType)
}

