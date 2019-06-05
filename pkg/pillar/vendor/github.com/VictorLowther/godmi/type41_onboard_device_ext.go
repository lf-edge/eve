/*
* File Name:	type41_onboard_device_ext.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type OnBoardDevicesExtendedInformationType byte

const (
	OnBoardDevicesExtendedInformationTypeOther OnBoardDevicesExtendedInformationType = 1 + iota
	OnBoardDevicesExtendedInformationTypeUnknown
	OnBoardDevicesExtendedInformationTypeVideo
	OnBoardDevicesExtendedInformationTypeSCSIController
	OnBoardDevicesExtendedInformationTypeEthernet
	OnBoardDevicesExtendedInformationTypeTokenRing
	OnBoardDevicesExtendedInformationTypeSound
	OnBoardDevicesExtendedInformationTypePATAController
	OnBoardDevicesExtendedInformationTypeSATAController
	OnBoardDevicesExtendedInformationTypeSASController
)

func (o OnBoardDevicesExtendedInformationType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"Video",
		"SCSI Controller",
		"Ethernet",
		"Token Ring",
		"Sound",
		"PATA Controller",
		"SATA Controller",
		"SAS Controller",
	}
	return types[o-1]
}

type OnBoardDevicesExtendedInformation struct {
	infoCommon
	ReferenceDesignation string
	DeviceType           OnBoardDevicesExtendedInformationType
	DeviceTypeInstance   byte
	SegmentGroupNumber   uint16
	BusNumber            byte
	DeviceFunctionNumber byte
}

func (o OnBoardDevicesExtendedInformation) SlotSegment() string {
	if o.SegmentGroupNumber == 0xFFFF || o.BusNumber == 0xFF || o.DeviceFunctionNumber == 0xFF {
		return "Not of types PCI/AGP/PCI-X/PCI-Express"
	}
	return fmt.Sprintf("Bus Address: %04x:%02x:%02x.%x",
		o.SegmentGroupNumber,
		o.BusNumber,
		o.DeviceFunctionNumber>>3,
		o.DeviceFunctionNumber&0x7)
}

func (o OnBoardDevicesExtendedInformation) String() string {
	return fmt.Sprintf("On Board Devices Extended Information\n"+
		"\tReference Designation: %s\n"+
		"\tDevice Type: %s\n"+
		"\tDevice Type Instance: %d\n"+
		"%s\n",
		o.ReferenceDesignation,
		o.DeviceType,
		o.DeviceTypeInstance,
		o.SlotSegment())
}
