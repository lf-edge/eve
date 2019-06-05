/*
* File Name:	type7_cache.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-19
 */
package godmi

import (
	"fmt"
	"strconv"
)

type CacheOperationalMode byte

const (
	CacheOperationalModeWriteThrough CacheOperationalMode = iota
	CacheOperationalModeWriteBack
	CacheOperationalModeVariesWithMemoryAddress
	CacheOperationalModeUnknown
)

func (c CacheOperationalMode) String() string {
	modes := [...]string{
		"Write Through",
		"Write Back",
		"Varies With Memory Address",
		"Unknown",
	}
	return modes[c]
}

type CacheLocation byte

const (
	CacheLocationInternal CacheLocation = iota
	CacheLocationExternal
	CacheLocationReserved
	CacheLocationUnknown
)

func (c CacheLocation) String() string {
	locations := [...]string{
		"Internal",
		"External",
		"Reserved",
		"Unknown",
	}
	return locations[c]
}

type CacheLevel byte

const (
	CacheLevel1 CacheLevel = iota
	CacheLevel2
	CacheLevel3
)

func (c CacheLevel) String() string {
	levels := [...]string{
		"Level1",
		"Level2",
		"Level3",
	}
	return levels[c]
}

type CacheConfiguration struct {
	Mode     CacheOperationalMode
	Enabled  bool
	Location CacheLocation
	Socketed bool
	Level    CacheLevel
}

func NewCacheConfiguration(u uint16) CacheConfiguration {
	var c CacheConfiguration
	c.Level = CacheLevel(byte(u & 0x7))
	c.Socketed = CheckBit(uint64(u), 3)
	c.Location = CacheLocation((u >> 5) & 0x3)
	c.Enabled = CheckBit(uint64(u), 7)
	c.Mode = CacheOperationalMode((u >> 8) & 0x3)
	return c
}

func (c CacheConfiguration) String() string {
	return fmt.Sprintf("Cache Configuration:\n"+
		"\tLevel: %s\n"+
		"\tSocketed: %v\n"+
		"\tLocation: %s\n"+
		"\tEnabled: %v\n"+
		"\tMode: %s\n\t\t",
		c.Level,
		c.Socketed,
		c.Location,
		c.Enabled,
		c.Mode)
}

type CacheGranularity byte

const (
	CacheGranularity1K CacheGranularity = iota
	CacheGranularity64K
)

func (c CacheGranularity) String() string {
	grans := [...]string{
		"1K",
		"64K",
	}
	return grans[c]
}

type CacheSize struct {
	Granularity CacheGranularity
	Size        uint16
}

func NewCacheSize(u uint16) CacheSize {
	var c CacheSize
	c.Granularity = CacheGranularity(u >> 15)
	c.Size = u &^ (uint16(1) << 15)
	return c
}

func (c CacheSize) String() string {
	return fmt.Sprintf("%d * %s", c.Size, c.Granularity)
}

type CacheSRAMType uint16

const (
	CacheSRAMTypeOther CacheSRAMType = 1 << iota
	CacheSRAMTypeUnknown
	CacheSRAMTypeNonBurst
	CacheSRAMTypeBurst
	CacheSRAMTypePipelineBurst
	CacheSRAMTypeSynchronous
	CacheSRAMTypeAsynchronous
	CacheSRAMTypeReserved
)

func (c CacheSRAMType) String() string {
	//types := [...]string{
	//	"Other",
	//	"Unknown",
	//	"Non-Burst",
	//	"Burst",
	//	"Pipeline Burst",
	//	"Synchronous",
	//	"Asynchronous",
	//	"Reserved",
	//}
	var ret string
	if CheckBit(uint64(c), 0) {
		ret += "other"
	}
	if CheckBit(uint64(c), 1) {
		ret += "Unknown"
	}
	if CheckBit(uint64(c), 2) {
		ret += "Non-Burst"
	}
	if CheckBit(uint64(c), 3) {
		ret += "Burst"
	}
	if CheckBit(uint64(c), 4) {
		ret += "Pipeline Burst"
	}
	if CheckBit(uint64(c), 5) {
		ret += "Synchronous"
	}
	if CheckBit(uint64(c), 6) {
		ret += "Asynchronous"
	}
	return ret
}

type CacheSpeed byte

func (s CacheSpeed) String() string {
	speed := int(s)
	if speed == 0 {
		return "Unknown"
	}
	return strconv.Itoa(speed)
}

type CacheErrorCorrectionType byte

const (
	CacheErrorCorrectionTypeOther CacheErrorCorrectionType = 1 + iota
	CacheErrorCorrectionTypeUnknown
	CacheErrorCorrectionTypeNone
	CacheErrorCorrectionTypeParity
	CacheErrorCorrectionTypeSinglebitECC
	CacheErrorCorrectionTypeMultibitECC
)

func (c CacheErrorCorrectionType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"None",
		"Parity",
		"Single-bit ECC",
		"Multi-bit ECC",
	}
	return types[c-1]
}

type CacheSystemCacheType byte

const (
	CacheSystemCacheTypeOther CacheSystemCacheType = 1 + iota
	CacheSystemCacheTypeUnknown
	CacheSystemCacheTypeInstruction
	CacheSystemCacheTypeData
	CacheSystemCacheTypeUnified
)

func (c CacheSystemCacheType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"Instruction",
		"Data",
		"Unified",
	}
	return types[c-1]
}

type CacheAssociativity byte

const (
	CacheAssociativityOther CacheAssociativity = 1 + iota
	CacheAssociativityUnknown
	CacheAssociativityDirectMapped
	CacheAssociativity2waySetAssociative
	CacheAssociativity4waySetAssociative
	CacheAssociativityFullyAssociative
	CacheAssociativity8waySetAssociative
	CacheAssociativity16waySetAssociative
	CacheAssociativity12waySetAssociative
	CacheAssociativity24waySetAssociative
	CacheAssociativity32waySetAssociative
	CacheAssociativity48waySetAssociative
	CacheAssociativity64waySetAssociative
	CacheAssociativity20waySetAssociative
)

func (c CacheAssociativity) String() string {
	caches := [...]string{
		"Reserved",
		"Other",
		"Unknown",
		"Direct Mapped",
		"2-way Set-Associative",
		"4-way Set-Associative",
		"Fully Associative",
		"8-way Set-Associative",
		"16-way Set-Associative",
		"12-way Set-Associative",
		"24-way Set-Associative",
		"32-way Set-Associative",
		"48-way Set-Associative",
		"64-way Set-Associative",
		"20-way Set-Associative",
	}
	return caches[c]
}

type CacheInformation struct {
	infoCommon
	SocketDesignation   string
	Configuration       CacheConfiguration
	MaximumCacheSize    CacheSize
	InstalledSize       CacheSize
	SupportedSRAMType   CacheSRAMType
	CurrentSRAMType     CacheSRAMType
	CacheSpeed          CacheSpeed
	ErrorCorrectionType CacheErrorCorrectionType
	SystemCacheType     CacheSystemCacheType
	Associativity       CacheAssociativity
}

func (c CacheInformation) String() string {
	return fmt.Sprintf("Cache Information\n"+
		"\tSocket Designation: %s\n"+
		"\tConfiguration: %s\n"+
		"\tMaximum Cache Size: %s\n"+
		"\tInstalled Size: %s\n"+
		"\tSupportedSRAM Type: %s\n"+
		"\tCurrentSRAM Type: %s\n"+
		"\tCache Speed: %s\n"+
		"\tError Correction Type: %s\n"+
		"\tSystem Cache Type: %s\n"+
		"\tAssociativity: %s",
		c.SocketDesignation,
		c.Configuration,
		c.MaximumCacheSize,
		c.InstalledSize,
		c.SupportedSRAMType,
		c.CurrentSRAMType,
		c.CacheSpeed,
		c.ErrorCorrectionType,
		c.SystemCacheType,
		c.Associativity)
}

func newCacheInformation(h dmiHeader) dmiTyper {
	data := h.data
	ci := &CacheInformation{
		SocketDesignation:   h.FieldString(int(data[0x04])),
		Configuration:       NewCacheConfiguration(u16(data[0x05:0x07])),
		MaximumCacheSize:    NewCacheSize(u16(data[0x07:0x09])),
		InstalledSize:       NewCacheSize(u16(data[0x09:0x0B])),
		SupportedSRAMType:   CacheSRAMType(u16(data[0x0B:0x0D])),
		CurrentSRAMType:     CacheSRAMType(u16(data[0x0D:0x0F])),
		CacheSpeed:          CacheSpeed(data[0x0F]),
		ErrorCorrectionType: CacheErrorCorrectionType(data[0x10]),
		SystemCacheType:     CacheSystemCacheType(data[0x11]),
		Associativity:       CacheAssociativity(data[0x12]),
	}
	CacheInformations = append(CacheInformations, ci)
	return ci
}

var CacheInformations []*CacheInformation

func GetCacheInformation() string {
	var ret string
	for i, v := range CacheInformations {
		ret += "\n Cache infomation index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeCache, newCacheInformation)
}
