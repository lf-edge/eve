/*
* File Name:	type9_systemslot.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type SystemSlotType byte

const (
	SystemSlotTypeOther SystemSlotType = 1 + iota
	SystemSlotTypeUnknown
	SystemSlotTypeISA
	SystemSlotTypeMCA
	SystemSlotTypeEISA
	SystemSlotTypePCI
	SystemSlotTypePCCardPCMCIA
	SystemSlotTypeVL_VESA
	SystemSlotTypeProprietary
	SystemSlotTypeProcessorCardSlot
	SystemSlotTypeProprietaryMemoryCardSlot
	SystemSlotTypeIORiserCardSlot
	SystemSlotTypeNuBus
	SystemSlotTypePCI_66MHzCapable
	SystemSlotTypeAGP
	SystemSlotTypeAGP2X
	SystemSlotTypeAGP4X
	SystemSlotTypePCI_X
	SystemSlotTypeAGP8X
	SystemSlotTypeM2Socket1DP
	SystemSlotTypeM2Socket1SP
	SystemSlotTypeM2Socket2
	SystemSlotTypeM2Socket3
	SystemSlotTypeMXMType1
	SystemSlotTypeMXMType2
	SystemSlotTypeMXMType3_StandardConnector
	SystemSlotTypeMXMType3_HEConnector
	SystemSlotTypeMXMType4
	SystemSlotTypeMXM3TypeA
	SystemSlotTypeMXM3TypeB
	SystemSlotTypePCIExpressGen2SFF_8639
	SystemSlotTypePCIExpressGen3SFF_8639
	SystemSlotTypePCIExpressMini52_pin_WithBottomSide
	SystemSlotTypePCIExpressMini52_pin_WithoutBottomSide
	SystemSlotTypePCIExpressMini76_pin
	SystemSlotTypePC_98C20
	SystemSlotTypePC_98C24
	SystemSlotTypePC_98E
	SystemSlotTypePC_98LocalBus
	SystemSlotTypePC_98Card
	SystemSlotTypePCIExpress
	SystemSlotTypePCIExpressx1
	SystemSlotTypePCIExpressx2
	SystemSlotTypePCIExpressx4
	SystemSlotTypePCIExpressx8
	SystemSlotTypePCIExpressx16
	SystemSlotTypePCIExpressGen2
	SystemSlotTypePCIExpressGen2x1
	SystemSlotTypePCIExpressGen2x2
	SystemSlotTypePCIExpressGen2x4
	SystemSlotTypePCIExpressGen2x8
	SystemSlotTypePCIExpressGen2x16
	SystemSlotTypePCIExpressGen3
	SystemSlotTypePCIExpressGen3x1
	SystemSlotTypePCIExpressGen3x2
	SystemSlotTypePCIExpressGen3x4
	SystemSlotTypePCIExpressGen3x8
	SystemSlotTypePCIExpressGen3x16
)

func (s SystemSlotType) String() string {
	types := [...]string{
		"Other", // 0x01
		"Unknown",
		"ISA",
		"MCA",
		"EISA",
		"PCI",
		"PC Card (PCMCIA)",
		"VL-VESA",
		"Proprietary",
		"Processor Card Slot",
		"Proprietary Memory Card Slot",
		"I/O Riser Card Slot",
		"NuBus",
		"PCI – 66MHz Capable",
		"AGP",
		"AGP 2X",
		"AGP 4X",
		"PCI-X",
		"AGP 8X",
		"M.2 Socket 1-DP (Mechanical Key A)",
		"M.2 Socket 1-SD (Mechanical Key E)",
		"M.2 Socket 2 (Mechanical Key B)",
		"M.2 Socket 3 (Mechanical Key M)",
		"MXM Type I",
		"MXM Type II",
		"MXM Type III (standard connector)",
		"MXM Type III (HE connector)",
		"MXM Type IV",
		"MXM 3.0 Type A",
		"MXM 3.0 Type B",
		"PCI Express Gen 2 SFF-8639",
		"PCI Express Gen 3 SFF-8639",
		"PCI Express Mini 52-pin (CEM spec. 2.0) with bottom-side keep-outs",
		"PCI Express Mini 52-pin (CEM spec. 2.0) without bottom-side keep-outs",
		"PCI Express Mini 76-pin", // 0x23
	}
	types2 := [...]string{
		"PC-98/C20", //0xa0
		"PC-98/C24",
		"PC-98/E",
		"PC-98/Local Bus",
		"PC-98/Card",
		"PCI Express",
		"PCI Express x1",
		"PCI Express x2",
		"PCI Express x4",
		"PCI Express x8",
		"PCI Express x16",
		"PCI Express Gen 2",
		"PCI Express Gen 2 x1",
		"PCI Express Gen 2 x2",
		"PCI Express Gen 2 x4",
		"PCI Express Gen 2 x8",
		"PCI Express Gen 2 x16",
		"PCI Express Gen 3",
		"PCI Express Gen 3 x1",
		"PCI Express Gen 3 x2",
		"PCI Express Gen 3 x4",
		"PCI Express Gen 3 x8",
		"PCI Express Gen 3 x16",
	}
	if s < 0xa0 {
		return types[s-1]
	}
	return types2[s-0xa0]
}

type SystemSlotDataBusWidth byte

const (
	SystemSlotDataBusWidthOther SystemSlotDataBusWidth = 1 + iota
	SystemSlotDataBusWidthUnknown
	SystemSlotDataBusWidth8bit
	SystemSlotDataBusWidth16bit
	SystemSlotDataBusWidth32bit
	SystemSlotDataBusWidth64bit
	SystemSlotDataBusWidth128bit
	SystemSlotDataBusWidth1xorx1
	SystemSlotDataBusWidth2xorx2
	SystemSlotDataBusWidth4xorx4
	SystemSlotDataBusWidth8xorx8
	SystemSlotDataBusWidth12xorx12
	SystemSlotDataBusWidth16xorx16
	SystemSlotDataBusWidth32xorx32
)

func (s SystemSlotDataBusWidth) String() string {
	widths := [...]string{
		"Other",
		"Unknown",
		"8 bit",
		"16 bit",
		"32 bit",
		"64 bit",
		"128 bit",
		"1x or x1",
		"2x or x2",
		"4x or x4",
		"8x or x8",
		"12x or x12",
		"16x or x16",
		"32x or x32",
	}
	return widths[s-1]
}

type SystemSlotUsage byte

const (
	SystemSlotUsageOther SystemSlotUsage = 1 + iota
	SystemSlotUsageUnknown
	SystemSlotUsageAvailable
	SystemSlotUsageInuse
)

func (s SystemSlotUsage) String() string {
	usages := [...]string{
		"Other",
		"Unknown",
		"Available",
		"In use",
	}
	return usages[s-1]
}

type SystemSlotLength byte

const (
	SystemSlotLengthOther SystemSlotLength = 1 + iota
	SystemSlotLengthUnknown
	SystemSlotLengthShortLength
	SystemSlotLengthLongLength
)

func (s SystemSlotLength) String() string {
	lengths := [...]string{
		"Other",
		"Unknown",
		"Short Length",
		"Long Length",
	}
	return lengths[s-1]
}

type SystemSlotID uint16

type SystemSlotCharacteristics1 byte

const (
	SystemSlotCharacteristicsunknown SystemSlotCharacteristics1 = 1 << iota
	SystemSlotCharacteristicsProvides5_0volts
	SystemSlotCharacteristicsProvides3_3volts
	SystemSlotCharacteristicsSlotsopeningissharedwithanotherslot
	SystemSlotCharacteristicsPCCardslotsupportsPCCard_16
	SystemSlotCharacteristicsPCCardslotsupportsCardBus
	SystemSlotCharacteristicsPCCardslotsupportsZoomVideo
	SystemSlotCharacteristicsPCCardslotsupportsModemRingResume
)

func (s SystemSlotCharacteristics1) String() string {
	chars := [...]string{
		"Characteristics unknown.",
		"Provides 5.0 volts.",
		"Provides 3.3 volts.",
		"Slot’s opening is shared with another slot (for example, PCI/EISA shared slot).",
		"PC Card slot supports PC Card-16.",
		"PC Card slot supports CardBus.",
		"PC Card slot supports Zoom Video.",
		"PC Card slot supports Modem Ring Resume.",
	}
	return chars[s>>1]
}

type SystemSlotCharacteristics2 byte

const (
	SystemSlotCharacteristics2PCIslotsupportsPowerManagementEventsignal SystemSlotCharacteristics2 = 1 << iota
	SystemSlotCharacteristics2Slotsupportshot_plugdevices
	SystemSlotCharacteristics2PCIslotsupportsSMBussignal
	SystemSlotCharacteristics2Reserved
)

func (s SystemSlotCharacteristics2) String() string {
	chars := [...]string{
		"PCI slot supports Power Management Event (PME#) signal.",
		"Slot supports hot-plug devices.",
		"PCI slot supports SMBus signal.",
		"Reserved",
	}
	return chars[s>>1]
}

type SystemSlotSegmengGroupNumber uint16

type SystemSlotNumber byte

type SystemSlot struct {
	infoCommon
	Designation          string
	Type                 SystemSlotType
	DataBusWidth         SystemSlotDataBusWidth
	CurrentUsage         SystemSlotUsage
	Length               SystemSlotLength
	ID                   SystemSlotID
	Characteristics1     SystemSlotCharacteristics1
	Characteristics2     SystemSlotCharacteristics2
	SegmentGroupNumber   SystemSlotSegmengGroupNumber
	BusNumber            SystemSlotNumber
	DeviceFunctionNumber SystemSlotNumber
}

func (s SystemSlot) String() string {
	return fmt.Sprintf("System Slot Information\n"+
		"\tSlot Designation: %s\n"+
		"\tSlot Type: %s\n"+
		"\tSlot Data Bus Width: %s\n"+
		"\tCurrent Usage: %s\n"+
		"\tSlot Length: %s\n"+
		"\tSlot ID: %d\n"+
		"\tSlot Characteristics1: %s\n"+
		"\tSlot Characteristics2: %s\n"+
		"\tSegment Group Number: %d\n",
		//	"\tBus Number: %s\n"+
		// "\tDevice/Function Number: %s",
		s.Designation,
		s.Type,
		s.DataBusWidth,
		s.CurrentUsage,
		s.Length,
		s.ID,
		s.Characteristics1,
		s.Characteristics2,
		s.SegmentGroupNumber,
		// TODO:
		//	s.BusNumber,
		// s.DeviceFunctionNumber)
	)
}

func newSystemSlot(h dmiHeader) dmiTyper {
	data := h.data
	si := &SystemSlot{
		Designation:          h.FieldString(int(data[0x04])),
		Type:                 SystemSlotType(data[0x05]),
		DataBusWidth:         SystemSlotDataBusWidth(data[0x06]),
		CurrentUsage:         SystemSlotUsage(data[0x07]),
		Length:               SystemSlotLength(data[0x08]),
		ID:                   SystemSlotID(u16(data[0x09:0x0A])),
		Characteristics1:     SystemSlotCharacteristics1(data[0x0B]),
		Characteristics2:     SystemSlotCharacteristics2(data[0x0C]),
		SegmentGroupNumber:   SystemSlotSegmengGroupNumber(u16(data[0x0D:0x0F])),
		BusNumber:            SystemSlotNumber(data[0x0F]),
		DeviceFunctionNumber: SystemSlotNumber(data[0x10]),
	}
	SystemSlots = append(SystemSlots, si)
	return si
}

var SystemSlots []*SystemSlot

func GetSystemSlot() string {
	var ret string
	for i, v := range SystemSlots {
		ret += "\nSystem slot index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeSystemSlots, newSystemSlot)
}
