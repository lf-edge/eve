/*
* File Name:	type8_port.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */

package godmi

import (
	"fmt"
	"strconv"
)

type PortConnectorType byte

const (
	PortConnectorTypeNone PortConnectorType = iota
	PortConnectorTypeCentronics
	PortConnectorTypeMiniCentronics
	PortConnectorTypeProprietary
	PortConnectorTypeDB_25pinmale
	PortConnectorTypeDB_25pinfemale
	PortConnectorTypeDB_15pinmale
	PortConnectorTypeDB_15pinfemale
	PortConnectorTypeDB_9pinmale
	PortConnectorTypeDB_9pinfemale
	PortConnectorTypeRJ_11
	PortConnectorTypeRJ_45
	PortConnectorType50_pinMiniSCSI
	PortConnectorTypeMini_DIN
	PortConnectorTypeMicro_DIN
	PortConnectorTypePS2
	PortConnectorTypeInfrared
	PortConnectorTypeHP_HIL
	PortConnectorTypeAccessBusUSB
	PortConnectorTypeSSASCSI
	PortConnectorTypeCircularDIN_8male
	PortConnectorTypeCircularDIN_8female
	PortConnectorTypeOnBoardIDE
	PortConnectorTypeOnBoardFloppy
	PortConnectorType9_pinDualInlinepin10cut
	PortConnectorType25_pinDualInlinepin26cut
	PortConnectorType50_pinDualInline
	PortConnectorType68_pinDualInline
	PortConnectorTypeOnBoardSoundInputfromCD_ROM
	PortConnectorTypeMini_CentronicsType_14
	PortConnectorTypeMini_CentronicsType_26
	PortConnectorTypeMini_jackheadphones
	PortConnectorTypeBNC
	PortConnectorType1394
	PortConnectorTypeSASSATAPlugReceptacle
	PortConnectorTypePC_98
	PortConnectorTypePC_98Hireso
	PortConnectorTypePC_H98
	PortConnectorTypePC_98Note
	PortConnectorTypePC_98Full
	PortConnectorTypeOther
)

func (p PortConnectorType) String() string {
	types := [...]string{
		"None",
		"Centronics",
		"Mini Centronics",
		"Proprietary",
		"DB-25 pin male",
		"DB-25 pin female",
		"DB-15 pin male",
		"DB-15 pin female",
		"DB-9 pin male",
		"DB-9 pin female",
		"RJ-11",
		"RJ-45",
		"50-pin MiniSCSI",
		"Mini-DIN",
		"Micro-DIN",
		"PS/2",
		"Infrared",
		"HP-HIL",
		"Access Bus (USB)",
		"SSA SCSI",
		"Circular DIN-8 male",
		"Circular DIN-8 female",
		"On Board IDE",
		"On Board Floppy",
		"9-pin Dual Inline (pin 10 cut)",
		"25-pin Dual Inline (pin 26 cut)",
		"50-pin Dual Inline",
		"68-pin Dual Inline",
		"On Board Sound Input from CD-ROM",
		"Mini-Centronics Type-14",
		"Mini-Centronics Type-26",
		"Mini-jack (headphones)",
		"BNC",
		"1394",
		"SAS/SATA Plug Receptacle",
		"PC-98",
		"PC-98Hireso",
		"PC-H98",
		"PC-98Note",
		"PC-98Full",
		"Other",
	}
	if p == 0xff {
		return "Other"
	}
	return types[p]
}

type PortType byte

const (
	PortTypeNone PortType = iota
	PortTypeParallelPortXTATCompatible
	PortTypeParallelPortPS2
	PortTypeParallelPortECP
	PortTypeParallelPortEPP
	PortTypeParallelPortECPEPP
	PortTypeSerialPortXTATCompatible
	PortTypeSerialPort16450Compatible
	PortTypeSerialPort16550Compatible
	PortTypeSerialPort16550ACompatible
	PortTypeSCSIPort
	PortTypeMIDIPort
	PortTypeJoyStickPort
	PortTypeKeyboardPort
	PortTypeMousePort
	PortTypeSSASCSI
	PortTypeUSB
	PortTypeFireWireIEEEP1394
	PortTypePCMCIATypeI2
	PortTypePCMCIATypeII
	PortTypePCMCIATypeIII
	PortTypeCardbus
	PortTypeAccessBusPort
	PortTypeSCSIII
	PortTypeSCSIWide
	PortTypePC_98
	PortTypePC_98_Hireso
	PortTypePC_H98
	PortTypeVideoPort
	PortTypeAudioPort
	PortTypeModemPort
	PortTypeNetworkPort
	PortTypeSATA
	PortTypeSAS
	PortType8251Compatible
	PortType8251FIFOCompatible
	PortTypeOther
)

func (p PortType) String() string {
	types := [...]string{
		"None",
		"Parallel Port XT/AT Compatible",
		"Parallel Port PS/2",
		"Parallel Port ECP",
		"Parallel Port EPP",
		"Parallel Port ECP/EPP",
		"Serial Port XT/AT Compatible",
		"Serial Port 16450 Compatible",
		"Serial Port 16550 Compatible",
		"Serial Port 16550A Compatible",
		"SCSI Port",
		"MIDI Port",
		"Joy Stick Port",
		"Keyboard Port",
		"Mouse Port",
		"SSA SCSI",
		"USB",
		"FireWire (IEEE P1394)",
		"PCMCIA Type I2",
		"PCMCIA Type II",
		"PCMCIA Type III",
		"Cardbus",
		"Access Bus Port",
		"SCSI II",
		"SCSI Wide",
		"PC-98",
		"PC-98-Hireso",
		"PC-H98",
		"Video Port",
		"Audio Port",
		"Modem Port",
		"Network Port",
		"SATA",
		"SAS",
		"8251 Compatible",
		"8251 FIFO Compatible",
		" Other",
	}
	if p == 0xff {
		return "Other"
	}
	return types[p]
}

type PortInformation struct {
	infoCommon
	InternalReferenceDesignator string
	InternalConnectorType       PortConnectorType
	ExternalReferenceDesignator string
	ExternalConnectorType       PortConnectorType
	Type                        PortType
}

func (p PortInformation) String() string {
	return fmt.Sprintf("Port Information\n"+
		"\tInternal Reference Designator: %s\n"+
		"\tInternal Connector Type: %s\n"+
		"\tExternal Reference Designator: %s\n"+
		"\tExternal Connector Type: %s\n"+
		"\tType: %s",
		p.InternalReferenceDesignator,
		p.InternalConnectorType,
		p.ExternalReferenceDesignator,
		p.ExternalConnectorType,
		p.Type)
}

func newPortInformation(h dmiHeader) dmiTyper {
	data := h.data
	pi := &PortInformation{
		InternalReferenceDesignator: h.FieldString(int(data[0x04])),
		InternalConnectorType:       PortConnectorType(data[0x05]),
		ExternalReferenceDesignator: h.FieldString(int(data[0x06])),
		ExternalConnectorType:       PortConnectorType(data[0x07]),
		Type: PortType(data[0x08]),
	}
	PortInformations = append(PortInformations, pi)
	return pi
}

var PortInformations []*PortInformation

func GetPortInformation() string {
	var ret string
	for i, v := range PortInformations {
		ret += "\nport infomation index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypePortConnector, newPortInformation)
}
