/*
* File Name:	type18_32bit_memory_error.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type MemoryErrorInformationType byte

func (m MemoryErrorInformationType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"OK",
		"Bad read",
		"Parity error",
		"Single-bit error",
		"Double-bit error",
		"Multi-bit error",
		"Nibble error",
		"Checksum error",
		"CRC error",
		"Corrected single-bit error",
		"Corrected error",
		"Uncorrectable error",
	}
	return types[m-1]
}

type MemoryErrorInformationGranularity byte

func (m MemoryErrorInformationGranularity) String() string {
	grans := [...]string{
		"Other",
		"Unknown",
		"Device level",
		"Memory partition level",
	}
	return grans[m-1]
}

type MemoryErrorInformationOperation byte

func (m MemoryErrorInformationOperation) String() string {
	operations := [...]string{
		"Other",
		"Unknown",
		"Read",
		"Write",
		"Partial write",
	}
	return operations[m-1]
}

type VendorSyndromeType uint32

func (v VendorSyndromeType) String() string {
	if v == 0x00000000 {
		return "Unknown"
	}
	return strconv.Itoa(int(v))
}

type ArrayErrorAddressType uint32

func (a ArrayErrorAddressType) String() string {
	if a == 0x80000000 {
		return "Unknown"
	}
	return strconv.Itoa(int(a))
}

type ResolutionType uint32

func (a ResolutionType) String() string {
	if a == 0x80000000 {
		return "Unknown"
	}
	return strconv.Itoa(int(a))
}

type ErrorAddressType uint32

func (a ErrorAddressType) String() string {
	if a == 0x80000000 {
		return "Unknown"
	}
	return strconv.Itoa(int(a))
}

type _32BitMemoryErrorInformation struct {
	infoCommon
	Type              MemoryErrorInformationType
	Granularity       MemoryErrorInformationGranularity
	Operation         MemoryErrorInformationOperation
	VendorSyndrome    VendorSyndromeType
	ArrayErrorAddress ArrayErrorAddressType
	ErrorAddress      ErrorAddressType
	Resolution        ResolutionType
}

func (m _32BitMemoryErrorInformation) String() string {
	return fmt.Sprintf("32 Bit Memory Error Information\n"+
		"\tError Type: %s\n"+
		"\tError Granularity: %s\n"+
		"\tError Operation: %s\n"+
		"\tVendor Syndrome: %s\n"+
		"\tMemory Array Error Address: %s\n"+
		"\tDevice Error Address: %s\n"+
		"\tError Resoluton: %s",
		m.Type,
		m.Granularity,
		m.Operation,
		m.VendorSyndrome,
		m.ArrayErrorAddress,
		m.ErrorAddress,
		m.Resolution,
	)
}

func new_32BitMemoryErrorInformation(h dmiHeader) dmiTyper {
	data := h.data
	bi := &_32BitMemoryErrorInformation{
		Type:              MemoryErrorInformationType(data[0x04]),
		Granularity:       MemoryErrorInformationGranularity(data[0x05]),
		Operation:         MemoryErrorInformationOperation(data[0x06]),
		VendorSyndrome:    VendorSyndromeType(u32(data[0x07:0x0B])),
		ArrayErrorAddress: ArrayErrorAddressType(u32(data[0x0B:0x0F])),
		ErrorAddress:      ErrorAddressType(u32(data[0x0F:0x13])),
		Resolution:        ResolutionType(u32(data[0x13:0x22])),
	}
	Bit32MemoryErrorInformations = append(Bit32MemoryErrorInformations, bi)
	return bi
}

var Bit32MemoryErrorInformations []*_32BitMemoryErrorInformation

func Get_32BitMemoryErrorInformation() string {
	var ret string
	for i, v := range Bit32MemoryErrorInformations {
		ret += "\n32-Bit Memory Error information index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureType32_bitMemoryError, new_32BitMemoryErrorInformation)
}
