/*
* File Name:	type0_bios.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-18 22:45:25
 */

package godmi

import (
	"encoding/json"
	"fmt"
	"strconv"
)

type BIOSCharacteristics [10]byte

var biosCharacteristics = [10][8]string{
	{
		"Reserved1",
		"Reserved2",
		"Reserved3",
		"BIOS characteristics not supported", /* 3 */
		"ISA is supported",
		"MCA is supported",
		"EISA is supported",
		"PCI is supported",
	},
	{
		"PC Card (PCMCIA) is supported",
		"PNP is supported",
		"APM is supported",
		"BIOS is upgradeable",
		"BIOS shadowing is allowed",
		"VLB is supported",
		"ESCD support is available",
		"Boot from CD is supported",
	},
	{
		"Selectable boot is supported",
		"BIOS ROM is socketed",
		"Boot from PC Card (PCMCIA) is supported",
		"EDD is supported",
		"Japanese floppy for NEC 9800 1.2 MB is supported (int 13h)",
		"Japanese floppy for Toshiba 1.2 MB is supported (int 13h)",
		"5.25\"/360 kB floppy services are supported (int 13h)",
		"5.25\"/1.2 MB floppy services are supported (int 13h)",
	},
	{
		"3.5\"/720 kB floppy services are supported (int 13h)",
		"3.5\"/2.88 MB floppy services are supported (int 13h)",
		"Print screen service is supported (int 5h)",
		"8042 keyboard services are supported (int 9h)",
		"Serial services are supported (int 14h)",
		"Printer services are supported (int 17h)",
		"CGA/mono video services are supported (int 10h)",
		"NEC PC-98"},
	{
		"BIOS Reserved 0",
		"BIOS Reserved 1",
		"BIOS Reserved 2",
		"BIOS Reserved 3",
		"BIOS Reserved 4",
		"BIOS Reserved 5",
		"BIOS Reserved 6",
		"BIOS Reserved 7",
	},
	{
		"BIOS Reserved 8",
		"BIOS Reserved 9",
		"BIOS Reserved a",
		"BIOS Reserved b",
		"BIOS Reserved c",
		"BIOS Reserved d",
		"BIOS Reserved e",
		"BIOS Reserved f",
	},
	{
		"System Reserved 0",
		"System Reserved 1",
		"System Reserved 2",
		"System Reserved 3",
		"System Reserved 4",
		"System Reserved 5",
		"System Reserved 6",
		"System Reserved 7",
	},
	{
		"System Reserved 8",
		"System Reserved 9",
		"System Reserved a",
		"System Reserved b",
		"System Reserved c",
		"System Reserved d",
		"System Reserved e",
		"System Reserved f",
	},
	{
		"ACPI is supported", /* 0 */
		"USB legacy is supported",
		"AGP is supported",
		"I2O boot is supported",
		"LS-120 boot is supported",
		"ATAPI Zip drive boot is supported",
		"IEEE 1394 boot is supported",
		"Smart battery is supported", /* 7 */
	},
	{
		"BIOS boot specification is supported", /* 0 */
		"Function key-initiated network boot is supported",
		"Targeted content distribution is supported",
		"UEFI is supported",
		"System is a virtual machine", /* 4 */
	},
}

func (b BIOSCharacteristics) toMap() map[string]bool {
	res := map[string]bool{}
	for segment := range b {
		for i := range biosCharacteristics {
			if b[segment]>>uint(i)&1 > 0 {
				res[biosCharacteristics[segment][i]] = true
			}
		}
	}
	return res
}

func (b BIOSCharacteristics) MarshalJSON() ([]byte, error) {
	ref := b.toMap()
	return json.Marshal(&ref)
}

func (b BIOSCharacteristics) String() string {
	var s string
	for segment := range b {
		for i := range biosCharacteristics {
			if b[segment]>>uint(i)&1 > 0 {
				s += "\n\t\t" + biosCharacteristics[segment][i]
			}
		}
	}
	return s
}

type BIOSRuntimeSize uint

func (b BIOSRuntimeSize) String() string {
	if (b & 0x3FF) > 0 {
		return fmt.Sprintf("%d Bytes", b)
	}
	return fmt.Sprintf("%d kB", b>>10)
}

type BIOSRomSize byte

func (b BIOSRomSize) String() string {
	return fmt.Sprintf("%d kB", uint(b+1)*64)
}

type BIOSInformation struct {
	infoCommon
	Vendor                                 string
	BIOSVersion                            string
	StartingAddressSegment                 uint16
	ReleaseDate                            string
	RomSize                                BIOSRomSize
	RuntimeSize                            BIOSRuntimeSize
	Characteristics                        BIOSCharacteristics
	SystemBIOSMajorRelease                 byte
	SystemBIOSMinorRelease                 byte
	EmbeddedControllerFirmwareMajorRelease byte
	EmbeddedControllerFirmawreMinorRelease byte
}

func (b BIOSInformation) String() string {
	s := fmt.Sprintf("BIOS Information\n"+
		"\tVendor: %s\n"+
		"\tVersion: %s\n"+
		"\tRelease Date: %s\n"+
		"\tAddress: 0x%4X0\n"+
		"\tRuntime Size: %s\n"+
		"\tROM Size: %s\n"+
		"\tCharacteristics:%s",
		b.Vendor,
		b.BIOSVersion,
		b.ReleaseDate,
		b.StartingAddressSegment,
		b.RuntimeSize,
		b.RomSize,
		b.Characteristics)
	return s
}

var BIOSInformations []*BIOSInformation

func newBIOSInformation(h dmiHeader) dmiTyper {
	data := h.data
	sas := u16(data[0x06:0x08])
	bi := &BIOSInformation{
		Vendor:                 h.FieldString(int(data[0x04])),
		BIOSVersion:            h.FieldString(int(data[0x05])),
		StartingAddressSegment: sas,
		ReleaseDate:            h.FieldString(int(data[0x08])),
		RomSize:                BIOSRomSize(data[0x09]),
		RuntimeSize:            BIOSRuntimeSize((uint(0x10000) - uint(sas)) << 4),
		Characteristics:        BIOSCharacteristics([10]byte{}),
	}
	copy(bi.Characteristics[:], data[0x0A:0x12])
	if h.length >= 0x13 {
		bi.Characteristics[8] = data[0x12]
	}
	if h.length >= 0x14 {
		bi.Characteristics[9] = data[0x13]
	}
	BIOSInformations = append(BIOSInformations, bi)

	return bi
}

func GetBIOSInformation() string {
	var ret string
	for i, v := range BIOSInformations {
		ret += "\n BIOSInfomation index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeBIOS, newBIOSInformation)
}
