/*
* File Name:	type38_ipmi_device.go
* Description:	
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-20
*/
package godmi

import (
	"fmt"
)

type IPMIDeviceInformationInterfaceType byte

const (
	IPMIDeviceInformationInterfaceTypeUnknown IPMIDeviceInformationInterfaceType = 1 + iota
	IPMIDeviceInformationInterfaceTypeKCSKeyboardControllerStyle
	IPMIDeviceInformationInterfaceTypeSMICServerManagementInterfaceChip
	IPMIDeviceInformationInterfaceTypeBTBlockTransfer
	IPMIDeviceInformationInterfaceTypeReservedforfutureassignmentbythisspecification
)

func (i IPMIDeviceInformationInterfaceType) String() string {
	types := [...]string{
		"Unknown",
		"KCS: Keyboard Controller Style",
		"SMIC: Server Management Interface Chip",
		"BT: Block Transfer",
		"Reserved for future assignment by this specification",
	}
	if i <= 3 {
		return types[i]
	}
	return types[4]
}

type IPMIDeviceInformationInfo byte

const (
	IPMIDeviceInformationInfoNotSpecified IPMIDeviceInformationInfo = iota
	IPMIDeviceInformationInfoSpecified
)

func (i IPMIDeviceInformationInfo) String() string {
	info := [...]string{
		"not specified",
		"specified",
	}
	return info[i]
}

type IPMIDeviceInformationPolarity byte

const (
	IPMIDeviceInformationPolarityActiveLow IPMIDeviceInformationPolarity = iota
	IPMIDeviceInformationPolarityActiveHigh
)

func (i IPMIDeviceInformationPolarity) String() string {
	polarities := [...]string{
		"active low",
		"active high",
	}
	return polarities[i]
}

type IPMIDeviceInformationTriggerMode byte

const (
	IPMIDeviceInformationTriggerModeEdge IPMIDeviceInformationTriggerMode = iota
	IPMIDeviceInformationTriggerModeLevel
)

func (i IPMIDeviceInformationTriggerMode) String() string {
	modes := [...]string{
		"edge",
		"level",
	}
	return modes[i]
}

type IPMIDeviceInformationInterruptInfo struct {
	Info        IPMIDeviceInformationInfo
	Polarity    IPMIDeviceInformationPolarity
	TriggerMode IPMIDeviceInformationTriggerMode
}

type IPMIDeviceInformationRegisterSpacing byte

const (
	IPMIDeviceInformationRegisterSpacingSuccessiveByteBoundaries IPMIDeviceInformationRegisterSpacing = iota
	IPMIDeviceInformationRegisterSpacing32BitBoundaries
	IPMIDeviceInformationRegisterSpacing16ByteBoundaries
	IPMIDeviceInformationRegisterSpacingReserved
)

func (i IPMIDeviceInformationRegisterSpacing) String() string {
	space := [...]string{
		"Interface registers are on successive byte boundaries",
		"Interface registers are on 32-bit boundaries",
		"Interface registers are on 16-byte boundaries",
		"Reserved",
	}
	return space[i]
}

type IPMIDeviceInformationLSbit byte

type IPMIDeviceInformationBaseModifier struct {
	RegisterSpacing IPMIDeviceInformationRegisterSpacing
	LSbit           IPMIDeviceInformationLSbit
}

type IPMIDeviceInformationAddressModiferInterruptInfo struct {
	BaseAddressModifier IPMIDeviceInformationBaseModifier
	InterruptInfo       IPMIDeviceInformationInterruptInfo
}

func (i IPMIDeviceInformationAddressModiferInterruptInfo) String() string {
	return fmt.Sprintf("\tBase Address Modifier:\n"+
		"\t\tRegister spacing: %s\n"+
		"\t\tLs-bit for addresses: %d\n"+
		"\tInterrupt Info:\n"+
		"\t\tInfo: %s\n"+
		"\t\tPolarity: %s\n"+
		"\t\tTrigger Mode: %s",
		i.BaseAddressModifier.RegisterSpacing,
		i.BaseAddressModifier.LSbit,
		i.InterruptInfo.Info,
		i.InterruptInfo.Polarity,
		i.InterruptInfo.TriggerMode)
}

func newIPMIDeviceInformationAddressModiferInterruptInfo(base byte) IPMIDeviceInformationAddressModiferInterruptInfo {
	var ipmi IPMIDeviceInformationAddressModiferInterruptInfo
	ipmi.BaseAddressModifier.RegisterSpacing = IPMIDeviceInformationRegisterSpacing((base & 0xC0) >> 6)
	ipmi.BaseAddressModifier.LSbit = IPMIDeviceInformationLSbit((base & 0x10) >> 4)
	ipmi.InterruptInfo.Info = IPMIDeviceInformationInfo((base & 0x08) >> 3)
	ipmi.InterruptInfo.Polarity = IPMIDeviceInformationPolarity((base & 0x02) >> 1)
	ipmi.InterruptInfo.TriggerMode = IPMIDeviceInformationTriggerMode(base & 0x01)
	return ipmi
}

type IPMIDeviceInformation struct {
	infoCommon
	InterfaceType                  IPMIDeviceInformationInterfaceType
	Revision                       byte
	I2CSlaveAddress                byte
	NVStorageAddress               byte
	BaseAddress                    uint64
	BaseAddressModiferInterrutInfo IPMIDeviceInformationAddressModiferInterruptInfo
	InterruptNumbe                 byte
}

func (i IPMIDeviceInformation) String() string {
	return fmt.Sprintf("IPMI Device Information\n"+
		"\tInterface Type: %s\n"+
		"\tRevision: %d\n"+
		"\tI2C Slave Address: %d\n"+
		"\tNV Storage Address: %d\n"+
		"\tBase Address: %d\n"+
		"\tBase Address Modifer Interrut Info: %s\n"+
		"\tInterrupt Numbe: %d",
		i.InterfaceType,
		i.Revision,
		i.I2CSlaveAddress,
		i.NVStorageAddress,
		i.BaseAddress,
		i.BaseAddressModiferInterrutInfo,
		i.InterruptNumbe)
}


