/*
* File Name:	type16_phymem.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */

package godmi

import (
	"fmt"
	"strconv"
)

type PhysicalMemoryArrayLocation byte

const (
	PhysicalMemoryArrayLocationOther PhysicalMemoryArrayLocation = 1 + iota
	PhysicalMemoryArrayLocationUnknown
	PhysicalMemoryArrayLocationSystemboardormotherboard
	PhysicalMemoryArrayLocationISAadd_oncard
	PhysicalMemoryArrayLocationEISAadd_oncard
	PhysicalMemoryArrayLocationPCIadd_oncard
	PhysicalMemoryArrayLocationMCAadd_oncard
	PhysicalMemoryArrayLocationPCMCIAadd_oncard
	PhysicalMemoryArrayLocationProprietaryadd_oncard
	PhysicalMemoryArrayLocationNuBus
	PhysicalMemoryArrayLocationPC_98C20add_oncard
	PhysicalMemoryArrayLocationPC_98C24add_oncard
	PhysicalMemoryArrayLocationPC_98Eadd_oncard
	PhysicalMemoryArrayLocationPC_98Localbusadd_oncard
)

func (p PhysicalMemoryArrayLocation) String() string {
	locations := [...]string{
		"Other",
		"Unknown",
		"System board or motherboard",
		"ISA add-on card",
		"EISA add-on card",
		"PCI add-on card",
		"MCA add-on card",
		"PCMCIA add-on card",
		"Proprietary add-on card",
		"NuBus",
		"PC-98/C20 add-on card",
		"PC-98/C24 add-on card",
		"PC-98/E add-on card",
		"PC-98/Local bus add-on card",
	}
	return locations[p-1]
}

func (p PhysicalMemoryArrayLocation) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type PhysicalMemoryArrayUse byte

const (
	PhysicalMemoryArrayUseOther PhysicalMemoryArrayUse = 1 + iota
	PhysicalMemoryArrayUseUnknown
	PhysicalMemoryArrayUseSystemmemory
	PhysicalMemoryArrayUseVideomemory
	PhysicalMemoryArrayUseFlashmemory
	PhysicalMemoryArrayUseNon_volatileRAM
	PhysicalMemoryArrayUseCachememory
)

func (p PhysicalMemoryArrayUse) String() string {
	uses := [...]string{
		"Other",
		"Unknown",
		"System memory",
		"Video memory",
		"Flash memory",
		"Non-volatile RAM",
		"Cache memory",
	}
	return uses[p-1]
}

func (p PhysicalMemoryArrayUse) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type PhysicalMemoryArrayErrorCorrection byte

const (
	PhysicalMemoryArrayErrorCorrectionOther PhysicalMemoryArrayErrorCorrection = 1 + iota
	PhysicalMemoryArrayErrorCorrectionUnknown
	PhysicalMemoryArrayErrorCorrectionNone
	PhysicalMemoryArrayErrorCorrectionParity
	PhysicalMemoryArrayErrorCorrectionSingle_bitECC
	PhysicalMemoryArrayErrorCorrectionMulti_bitECC
	PhysicalMemoryArrayErrorCorrectionCRC
)

func (p PhysicalMemoryArrayErrorCorrection) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"None",
		"Parity",
		"Single-bit ECC",
		"Multi-bit ECC",
		"CRC",
	}
	return types[p-1]
}
func (p PhysicalMemoryArrayErrorCorrection) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type PhysicalMemoryArray struct {
	infoCommon
	Location               PhysicalMemoryArrayLocation
	Use                    PhysicalMemoryArrayUse
	ErrorCorrection        PhysicalMemoryArrayErrorCorrection
	MaximumCapacity        uint64
	ErrorInformationHandle uint16
	NumberOfMemoryDevices  uint16
}

func (p PhysicalMemoryArray) String() string {
	return fmt.Sprintf("Physcial Memory Array\n"+
		"\tLocation: %s\n"+
		"\tUse: %s\n"+
		"\tMemory Error Correction: %s\n"+
		"\tMaximum Capacity: %d\n"+
		"\tMemory Error Information Handle: %d\n"+
		"\tNumber of Memory Devices: %d\n",
		p.Location,
		p.Use,
		p.ErrorCorrection,
		p.MaximumCapacity,
		p.ErrorInformationHandle,
		p.NumberOfMemoryDevices)
}

func newPhysicalMemoryArray(h dmiHeader) dmiTyper {
	data := h.data
	res := &PhysicalMemoryArray{
		Location:               PhysicalMemoryArrayLocation(data[0x04]),
		Use:                    PhysicalMemoryArrayUse(data[0x05]),
		ErrorCorrection:        PhysicalMemoryArrayErrorCorrection(data[0x06]),
		MaximumCapacity:        uint64(u32(data[0x07:0x0B])),
		ErrorInformationHandle: u16(data[0x0B:0x0D]),
		NumberOfMemoryDevices:  u16(data[0x0D:0x0F]),
	}
	if res.MaximumCapacity == 0x80000000 {
		// the extended max capacity field is in bytes
		res.MaximumCapacity = u64(data[0x0F:])
	} else {
		// The original max capacity field is in kb.
		// Translate it into bytes
		res.MaximumCapacity <<= 10
	}
	PhysicalMemoryArrays = append(PhysicalMemoryArrays, res)
	return res
}

var PhysicalMemoryArrays []*PhysicalMemoryArray

func GetPhysicalMemory() *PhysicalMemoryArray {
	return PhysicalMemoryArrays[0]
}

func GetPhysicalMemoryArray() string {
	var ret string
	for i, v := range PhysicalMemoryArrays {
		ret += "\nPhysical Memory Arrays index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypePhysicalMemoryArray, newPhysicalMemoryArray)
}
