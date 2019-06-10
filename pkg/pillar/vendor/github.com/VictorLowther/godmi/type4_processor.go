/*
* File Name:	type4_processor.go
* Description:
* Author:	Chapman Ou <ochapman.cn@gmail.com>
* Created:	2014-08-18 23:18:50
 */
package godmi

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type ProcessorType byte

const (
	ProcessorTypeOther ProcessorType = 1 + iota
	ProcessorTypeUnknown
	ProcessorTypeCentralProcessor
	ProcessorTypeMathProcessor
	ProcessorTypeDSPProcessor
	ProcessorTypeVideoProcessor
)

func (p ProcessorType) String() string {
	types := [...]string{
		"Other",
		"Unknown",
		"CentralProcessor",
		"MathProcessor",
		"DSPProcessor",
		"VideoProcessor",
	}
	return types[p-1]
}

func (p ProcessorType) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type ProcessorFamily uint16

const (
	_ ProcessorFamily = iota
	ProcessorOther
	ProcessorUnknown
	ProcessorProcessorFamily8086
	ProcessorProcessorFamily80286
	ProcessorIntel386TMprocessor
	ProcessorIntel486TMprocessor
	ProcessorProcessorFamily8087
	ProcessorProcessorFamily80287
	ProcessorProcessorFamily80387
	ProcessorProcessorFamily80487
	ProcessorIntelPentiumprocessor
	ProcessorPentiumProprocessor
	ProcessorPentiumIIprocessor
	ProcessorPentiumprocessorwithMMXTMtechnology
	ProcessorIntelCeleronprocessor
	ProcessorPentiumIIXeonTMprocessor
	ProcessorPentiumIIIprocessor
	ProcessorM1Family
	ProcessorM2Family
	ProcessorIntelCeleronMprocessor
	ProcessorIntelPentium4HTprocessor
	_
	_
	ProcessorAMDDuronTMProcessorFamily
	ProcessorK5Family
	ProcessorK6Family
	ProcessorK6_2
	ProcessorK6_3
	ProcessorAMDAthlonTMProcessorFamily
	ProcessorAMD29000Family
	ProcessorK6_2Plus
	ProcessorPowerPCFamily
	ProcessorPowerPC601
	ProcessorPowerPC603
	ProcessorPowerPC603Plus
	ProcessorPowerPC604
	ProcessorPowerPC620
	ProcessorPowerPCx704
	ProcessorPowerPC750
	ProcessorIntelCoreTMDuoprocessor
	ProcessorIntelCoreTMDuomobileprocessor
	ProcessorIntelCoreTMSolomobileprocessor
	ProcessorIntelAtomTMprocessor
	_
	_
	_
	_
	ProcessorAlphaFamily
	ProcessorAlpha21064
	ProcessorAlpha21066
	ProcessorAlpha21164
	ProcessorAlpha21164PC
	ProcessorAlpha21164a
	ProcessorAlpha21264
	ProcessorAlpha21364
	ProcessorAMDTurionTMIIUltraDual_CoreMobileMProcessorFamily
	ProcessorAMDTurionTMIIDual_CoreMobileMProcessorFamily
	ProcessorAMDAthlonTMIIDual_CoreMProcessorFamily
	ProcessorAMDOpteronTM6100SeriesProcessor
	ProcessorAMDOpteronTM4100SeriesProcessor
	ProcessorAMDOpteronTM6200SeriesProcessor
	ProcessorAMDOpteronTM4200SeriesProcessor
	ProcessorAMDFXTMSeriesProcessor
	ProcessorMIPSFamily
	ProcessorMIPSR4000
	ProcessorMIPSR4200
	ProcessorMIPSR4400
	ProcessorMIPSR4600
	ProcessorMIPSR10000
	ProcessorAMDC_SeriesProcessor
	ProcessorAMDE_SeriesProcessor
	ProcessorAMDA_SeriesProcessor
	ProcessorAMDG_SeriesProcessor
	ProcessorAMDZ_SeriesProcessor
	ProcessorAMDR_SeriesProcessor
	ProcessorAMDOpteronTM4300SeriesProcessor
	ProcessorAMDOpteronTM6300SeriesProcessor
	ProcessorAMDOpteronTM3300SeriesProcessor
	ProcessorAMDFireProTMSeriesProcessor
	ProcessorSPARCFamily
	ProcessorSuperSPARC
	ProcessormicroSPARCII
	ProcessormicroSPARCIIep
	ProcessorUltraSPARC
	ProcessorUltraSPARCII
	ProcessorUltraSPARCIii
	ProcessorUltraSPARCIII
	ProcessorUltraSPARCIIIi
	_
	_
	_
	_
	_
	_
	_
	Processor68040Family
	Processor68xxx
	ProcessorProcessorFamily68000
	ProcessorProcessorFamily68010
	ProcessorProcessorFamily68020
	ProcessorProcessorFamily68030
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	ProcessorHobbitFamily
	_
	_
	_
	_
	_
	_
	_
	ProcessorCrusoeTMTM5000Family
	ProcessorCrusoeTMTM3000Family
	ProcessorEfficeonTMTM8000Family
	_
	_
	_
	_
	_
	ProcessorWeitek
	_
	ProcessorItaniumTMprocessor
	ProcessorAMDAthlonTM64ProcessorFamily
	ProcessorAMDOpteronTMProcessorFamily
	ProcessorAMDSempronTMProcessorFamily
	ProcessorAMDTurionTM64MobileTechnology
	ProcessorDual_CoreAMDOpteronTMProcessorFamily
	ProcessorAMDAthlonTM64X2Dual_CoreProcessorFamily
	ProcessorAMDTurionTM64X2MobileTechnology
	ProcessorQuad_CoreAMDOpteronTMProcessorFamily
	ProcessorThird_GenerationAMDOpteronTMProcessorFamily
	ProcessorAMDPhenomTMFXQuad_CoreProcessorFamily
	ProcessorAMDPhenomTMX4Quad_CoreProcessorFamily
	ProcessorAMDPhenomTMX2Dual_CoreProcessorFamily
	ProcessorAMDAthlonTMX2Dual_CoreProcessorFamily
	ProcessorPA_RISCFamily
	ProcessorPA_RISC8500
	ProcessorPA_RISC8000
	ProcessorPA_RISC7300LC
	ProcessorPA_RISC7200
	ProcessorPA_RISC7100LC
	ProcessorPA_RISC7100
	_
	_
	_
	_
	_
	_
	_
	_
	_
	ProcessorV30Family
	ProcessorQuad_CoreIntelXeonprocessor3200Series
	ProcessorDual_CoreIntelXeonprocessor3000Series
	ProcessorQuad_CoreIntelXeonprocessor5300Series
	ProcessorDual_CoreIntelXeonprocessor5100Series
	ProcessorDual_CoreIntelXeonprocessor5000Series
	ProcessorDual_CoreIntelXeonprocessorLV
	ProcessorDual_CoreIntelXeonprocessorULV
	ProcessorDual_CoreIntelXeonprocessor7100Series
	ProcessorQuad_CoreIntelXeonprocessor5400Series
	ProcessorQuad_CoreIntelXeonprocessor
	ProcessorDual_CoreIntelXeonprocessor5200Series
	ProcessorDual_CoreIntelXeonprocessor7200Series
	ProcessorQuad_CoreIntelXeonprocessor7300Series
	ProcessorQuad_CoreIntelXeonprocessor7400Series
	ProcessorMulti_CoreIntelXeonprocessor7400Series
	ProcessorPentiumIIIXeonTMprocessor
	ProcessorPentiumIIIProcessorwithIntelSpeedStepTMTechnology
	ProcessorPentium4Processor
	ProcessorIntelXeonprocessor
	ProcessorAS400Family
	ProcessorIntelXeonTMprocessorMP
	ProcessorAMDAthlonTMXPProcessorFamily
	ProcessorAMDAthlonTMMPProcessorFamily
	ProcessorIntelItanium2processor
	ProcessorIntelPentiumMprocessor
	ProcessorIntelCeleronDprocessor
	ProcessorIntelPentiumDprocessor
	ProcessorIntelPentiumProcessorExtremeEdition
	ProcessorIntelCoreTMSoloProcessor
	ProcessorReserved
	ProcessorIntelCoreTM2DuoProcessor
	ProcessorIntelCoreTM2Soloprocessor
	ProcessorIntelCoreTM2Extremeprocessor
	ProcessorIntelCoreTM2Quadprocessor
	ProcessorIntelCoreTM2Extrememobileprocessor
	ProcessorIntelCoreTM2Duomobileprocessor
	ProcessorIntelCoreTM2Solomobileprocessor
	ProcessorIntelCoreTMi7processor
	ProcessorDual_CoreIntelCeleronprocessor
	ProcessorIBM390Family
	ProcessorG4
	ProcessorG5
	ProcessorESA390G6
	ProcessorzArchitecturebase
	ProcessorIntelCoreTMi5processor
	ProcessorIntelCoreTMi3processor
	_
	_
	_
	ProcessorVIAC7TM_MProcessorFamily
	ProcessorVIAC7TM_DProcessorFamily
	ProcessorVIAC7TMProcessorFamily
	ProcessorVIAEdenTMProcessorFamily
	ProcessorMulti_CoreIntelXeonprocessor
	ProcessorDual_CoreIntelXeonprocessor3xxxSeries
	ProcessorQuad_CoreIntelXeonprocessor3xxxSeries
	ProcessorVIANanoTMProcessorFamily
	ProcessorDual_CoreIntelXeonprocessor5xxxSeries
	ProcessorQuad_CoreIntelXeonprocessor5xxxSeries
	_
	ProcessorDual_CoreIntelXeonprocessor7xxxSeries
	ProcessorQuad_CoreIntelXeonprocessor7xxxSeries
	ProcessorMulti_CoreIntelXeonprocessor7xxxSeries
	ProcessorMulti_CoreIntelXeonprocessor3400Series
	_
	_
	_
	ProcessorAMDOpteronTM3000SeriesProcessor
	ProcessorAMDSempronTMIIProcessor
	ProcessorEmbeddedAMDOpteronTMQuad_CoreProcessorFamily
	ProcessorAMDPhenomTMTriple_CoreProcessorFamily
	ProcessorAMDTurionTMUltraDual_CoreMobileProcessorFamily
	ProcessorAMDTurionTMDual_CoreMobileProcessorFamily
	ProcessorAMDAthlonTMDual_CoreProcessorFamily
	ProcessorAMDSempronTMSIProcessorFamily
	ProcessorAMDPhenomTMIIProcessorFamily
	ProcessorAMDAthlonTMIIProcessorFamily
	ProcessorSix_CoreAMDOpteronTMProcessorFamily
	ProcessorAMDSempronTMMProcessorFamily
	_
	_
	_
	_
	_
	_
	_
	_
	_
	_
	Processori860
	Processori960
	_
	_
	ProcessorIndicatortoobtaintheprocessorfamilyfromtheProcessorFamily2field
	_
	_
	_
	_
	_
	_
	ProcessorSH_3
	ProcessorSH_4
	ProcessorARM
	ProcessorStrongARM
	Processor6x86
	ProcessorMediaGX
	ProcessorMII
	ProcessorWinChip
	ProcessorDSP
	ProcessorVideoProcessor
	_
	_
)

func (p ProcessorFamily) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p ProcessorFamily) String() string {
	families := map[uint16]string{
		0x01: "Other",
		0x02: "Unknown",
		0x03: "8086",
		0x04: "80286",
		0x05: "80386",
		0x06: "80486",
		0x07: "8087",
		0x08: "80287",
		0x09: "80387",
		0x0A: "80487",
		0x0B: "Pentium",
		0x0C: "Pentium Pro",
		0x0D: "Pentium II",
		0x0E: "Pentium MMX",
		0x0F: "Celeron",
		0x10: "Pentium II Xeon",
		0x11: "Pentium III",
		0x12: "M1",
		0x13: "M2",
		0x14: "Celeron M",
		0x15: "Pentium 4 HT",

		0x18: "Duron",
		0x19: "K5",
		0x1A: "K6",
		0x1B: "K6-2",
		0x1C: "K6-3",
		0x1D: "Athlon",
		0x1E: "AMD29000",
		0x1F: "K6-2+",
		0x20: "Power PC",
		0x21: "Power PC 601",
		0x22: "Power PC 603",
		0x23: "Power PC 603+",
		0x24: "Power PC 604",
		0x25: "Power PC 620",
		0x26: "Power PC x704",
		0x27: "Power PC 750",
		0x28: "Core Duo",
		0x29: "Core Duo Mobile",
		0x2A: "Core Solo Mobile",
		0x2B: "Atom",
		0x2C: "Core M",
		0x2D: "Core m3",
		0x2E: "Core m5",
		0x2F: "Core m7",
		0x30: "Alpha",
		0x31: "Alpha 21064",
		0x32: "Alpha 21066",
		0x33: "Alpha 21164",
		0x34: "Alpha 21164PC",
		0x35: "Alpha 21164a",
		0x36: "Alpha 21264",
		0x37: "Alpha 21364",
		0x38: "Turion II Ultra Dual-Core Mobile M",
		0x39: "Turion II Dual-Core Mobile M",
		0x3A: "Athlon II Dual-Core M",
		0x3B: "Opteron 6100",
		0x3C: "Opteron 4100",
		0x3D: "Opteron 6200",
		0x3E: "Opteron 4200",
		0x3F: "FX",
		0x40: "MIPS",
		0x41: "MIPS R4000",
		0x42: "MIPS R4200",
		0x43: "MIPS R4400",
		0x44: "MIPS R4600",
		0x45: "MIPS R10000",
		0x46: "C-Series",
		0x47: "E-Series",
		0x48: "A-Series",
		0x49: "G-Series",
		0x4A: "Z-Series",
		0x4B: "R-Series",
		0x4C: "Opteron 4300",
		0x4D: "Opteron 6300",
		0x4E: "Opteron 3300",
		0x4F: "FirePro",
		0x50: "SPARC",
		0x51: "SuperSPARC",
		0x52: "MicroSPARC II",
		0x53: "MicroSPARC IIep",
		0x54: "UltraSPARC",
		0x55: "UltraSPARC II",
		0x56: "UltraSPARC IIi",
		0x57: "UltraSPARC III",
		0x58: "UltraSPARC IIIi",

		0x60: "68040",
		0x61: "68xxx",
		0x62: "68000",
		0x63: "68010",
		0x64: "68020",
		0x65: "68030",
		0x66: "Athlon X4",
		0x67: "Opteron X1000",
		0x68: "Opteron X2000",
		0x69: "Opteron A-Series",
		0x6A: "Opteron X3000",
		0x6B: "Zen",

		0x70: "Hobbit",

		0x78: "Crusoe TM5000",
		0x79: "Crusoe TM3000",
		0x7A: "Efficeon TM8000",

		0x80: "Weitek",

		0x82: "Itanium",
		0x83: "Athlon 64",
		0x84: "Opteron",
		0x85: "Sempron",
		0x86: "Turion 64",
		0x87: "Dual-Core Opteron",
		0x88: "Athlon 64 X2",
		0x89: "Turion 64 X2",
		0x8A: "Quad-Core Opteron",
		0x8B: "Third-Generation Opteron",
		0x8C: "Phenom FX",
		0x8D: "Phenom X4",
		0x8E: "Phenom X2",
		0x8F: "Athlon X2",
		0x90: "PA-RISC",
		0x91: "PA-RISC 8500",
		0x92: "PA-RISC 8000",
		0x93: "PA-RISC 7300LC",
		0x94: "PA-RISC 7200",
		0x95: "PA-RISC 7100LC",
		0x96: "PA-RISC 7100",

		0xA0: "V30",
		0xA1: "Quad-Core Xeon 3200",
		0xA2: "Dual-Core Xeon 3000",
		0xA3: "Quad-Core Xeon 5300",
		0xA4: "Dual-Core Xeon 5100",
		0xA5: "Dual-Core Xeon 5000",
		0xA6: "Dual-Core Xeon LV",
		0xA7: "Dual-Core Xeon ULV",
		0xA8: "Dual-Core Xeon 7100",
		0xA9: "Quad-Core Xeon 5400",
		0xAA: "Quad-Core Xeon",
		0xAB: "Dual-Core Xeon 5200",
		0xAC: "Dual-Core Xeon 7200",
		0xAD: "Quad-Core Xeon 7300",
		0xAE: "Quad-Core Xeon 7400",
		0xAF: "Multi-Core Xeon 7400",
		0xB0: "Pentium III Xeon",
		0xB1: "Pentium III Speedstep",
		0xB2: "Pentium 4",
		0xB3: "Xeon",
		0xB4: "AS400",
		0xB5: "Xeon MP",
		0xB6: "Athlon XP",
		0xB7: "Athlon MP",
		0xB8: "Itanium 2",
		0xB9: "Pentium M",
		0xBA: "Celeron D",
		0xBB: "Pentium D",
		0xBC: "Pentium EE",
		0xBD: "Core Solo",
		0xBE: "Core 2 or K7",
		0xBF: "Core 2 Duo",
		0xC0: "Core 2 Solo",
		0xC1: "Core 2 Extreme",
		0xC2: "Core 2 Quad",
		0xC3: "Core 2 Extreme Mobile",
		0xC4: "Core 2 Duo Mobile",
		0xC5: "Core 2 Solo Mobile",
		0xC6: "Core i7",
		0xC7: "Dual-Core Celeron",
		0xC8: "IBM390",
		0xC9: "G4",
		0xCA: "G5",
		0xCB: "ESA/390 G6",
		0xCC: "z/Architecture",
		0xCD: "Core i5",
		0xCE: "Core i3",

		0xD2: "C7-M",
		0xD3: "C7-D",
		0xD4: "C7",
		0xD5: "Eden",
		0xD6: "Multi-Core Xeon",
		0xD7: "Dual-Core Xeon 3xxx",
		0xD8: "Quad-Core Xeon 3xxx",
		0xD9: "Nano",
		0xDA: "Dual-Core Xeon 5xxx",
		0xDB: "Quad-Core Xeon 5xxx",

		0xDD: "Dual-Core Xeon 7xxx",
		0xDE: "Quad-Core Xeon 7xxx",
		0xDF: "Multi-Core Xeon 7xxx",
		0xE0: "Multi-Core Xeon 3400",

		0xE4: "Opteron 3000",
		0xE5: "Sempron II",
		0xE6: "Embedded Opteron Quad-Core",
		0xE7: "Phenom Triple-Core",
		0xE8: "Turion Ultra Dual-Core Mobile",
		0xE9: "Turion Dual-Core Mobile",
		0xEA: "Athlon Dual-Core",
		0xEB: "Sempron SI",
		0xEC: "Phenom II",
		0xED: "Athlon II",
		0xEE: "Six-Core Opteron",
		0xEF: "Sempron M",

		0xFA: "i860",
		0xFB: "i960",

		0x100: "ARMv7",
		0x101: "ARMv8",
		0x104: "SH-3",
		0x105: "SH-4",
		0x118: "ARM",
		0x119: "StrongARM",
		0x12C: "6x86",
		0x12D: "MediaGX",
		0x12E: "MII",
		0x140: "WinChip",
		0x15E: "DSP",
		0x1F4: "Video Processor",
	}
	res, ok := families[uint16(p)]
	if ok {
		return res
	}
	return fmt.Sprintf("Unknown processor family %x", uint16(p))
}

type ProcessorID uint64

type ProcessorVoltage byte

const (
	ProcessorVoltage5V ProcessorVoltage = 1 << iota
	ProcessorVoltage3dot3V
	ProcessorVoltage2dot9V
	ProcessorVoltageReserved
	_
	_
	_
	ProcessorVoltageLegacy
)

func (p ProcessorVoltage) String() string {
	if p&ProcessorVoltageLegacy == 0 {
		voltages := map[ProcessorVoltage]string{
			ProcessorVoltage5V:     "5V",
			ProcessorVoltage3dot3V: "3.3V",
			ProcessorVoltage2dot9V: "2.9V",
		}
		if v, ok := voltages[p]; ok {
			return v
		}
		return fmt.Sprintf("Unknown%d", int(p))
	}
	return fmt.Sprintf("%.1fV", float32(p-0x80)/10)
}

func (p ProcessorVoltage) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type ProcessorStatus byte

const (
	ProcessorStatusUnknown ProcessorStatus = iota
	ProcessorStatusEnabled
	ProcessorStatusDisabledByUser
	ProcessorStatusDisabledByBIOS
	ProcessorStatusIdle
	ProcessorStatusReserved1
	ProcessorStatusReserved2
	ProcessorStatusOther
)

func (p ProcessorStatus) String() string {
	// Bits 2:0
	status := [...]string{
		"Unknown", // 0
		"CPU Enabled",
		"Disabled By User through BIOS Setup",
		"Disabled By BIOS (POST Error)",
		"CPU is Idle, waiting to be enabled",
		"Reserved",
		"Reserved",
		"Other",
	}
	return status[p&0x07]
}

func (p ProcessorStatus) StringList() []string {
	// Bits 2:0
	status := [...]string{
		"Unknown", // 0
		"CPU Enabled",
		"Disabled By User through BIOS Setup",
		"Disabled By BIOS (POST Error)",
		"CPU is Idle, waiting to be enabled",
		"Reserved",
		"Reserved",
		"Other",
	}
	var ret []string
	ret = append(ret, status[p&0x07])

	if p&0x40 != 0 {
		ret = append(ret, "CPU Socket Populated")
	}
	return ret
}

func (p ProcessorStatus) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type ProcessorUpgrade byte

const (
	_ ProcessorUpgrade = iota
	ProcessorUpgradeOther
	ProcessorUpgradeUnknown
	ProcessorUpgradeDaughterBoard
	ProcessorUpgradeZIFSocket
	ProcessorUpgradeReplaceablePiggyBack
	ProcessorUpgradeNone
	ProcessorUpgradeLIFSocket
	ProcessorUpgradeSlot1
	ProcessorUpgradeSlot2
	ProcessorUpgrade370_pinsocket
	ProcessorUpgradeSlotA
	ProcessorUpgradeSlotM
	ProcessorUpgradeSocket423
	ProcessorUpgradeSocketASocket462
	ProcessorUpgradeSocket478
	ProcessorUpgradeSocket754
	ProcessorUpgradeSocket940
	ProcessorUpgradeSocket939
	ProcessorUpgradeSocketmPGA604
	ProcessorUpgradeSocketLGA771
	ProcessorUpgradeSocketLGA775
	ProcessorUpgradeSocketS1
	ProcessorUpgradeSocketAM2
	ProcessorUpgradeSocketF1207
	ProcessorUpgradeSocketLGA1366
	ProcessorUpgradeSocketG34
	ProcessorUpgradeSocketAM3
	ProcessorUpgradeSocketC32
	ProcessorUpgradeSocketLGA1156
	ProcessorUpgradeSocketLGA1567
	ProcessorUpgradeSocketPGA988A
	ProcessorUpgradeSocketBGA1288
	ProcessorUpgradeSocketrPGA988B
	ProcessorUpgradeSocketBGA1023
	ProcessorUpgradeSocketBGA1224
	ProcessorUpgradeSocketLGA1155
	ProcessorUpgradeSocketLGA1356
	ProcessorUpgradeSocketLGA2011
	ProcessorUpgradeSocketFS1
	ProcessorUpgradeSocketFS2
	ProcessorUpgradeSocketFM1
	ProcessorUpgradeSocketFM2
	ProcessorUpgradeSocketLGA2011_3
	ProcessorUpgradeSocketLGA1356_3
	ProcessorUpgradeSocketLGA1150
	ProcessorUpgradeSocketBGA1168
	ProcessorUpgradeSocketBGA1234
	ProcessorUpgradeSocketBGA1364
	ProcessorUpgradeSocketAM4
	ProcessorUpgradeSocketLGA1151
	ProcessorUpgradeSocketBGA1356
	ProcessorUpgradeSocketBGA1440
	ProcessorUpgradeSocketBGA1515
	ProcessorUpgradeSocketLGA3647_1
	ProcessorUpgradeSocketSP3
	ProcessorUpgradeSocketSP3r2
)

func (p ProcessorUpgrade) String() string {
	upgrades := [...]string{
		"THIS SHOULD NOT BE SEEN",
		"Other",
		"Unknown",
		"Daughter Board",
		"ZIF Socket",
		"Replaceable Piggy Back",
		"None",
		"LIF Socket",
		"Slot 1",
		"Slot 2",
		"370-pin socket",
		"Slot A",
		"Slot M",
		"Socket 423",
		"Socket A (Socket 462)",
		"Socket 478",
		"Socket 754",
		"Socket 940",
		"Socket 939",
		"Socket mPGA604",
		"Socket LGA771",
		"Socket LGA775",
		"Socket S1",
		"Socket AM2",
		"Socket F (1207)",
		"Socket LGA1366",
		"Socket G34",
		"Socket AM3",
		"Socket C32",
		"Socket LGA1156",
		"Socket LGA1567",
		"Socket PGA988A",
		"Socket BGA1288",
		"Socket rPGA988B",
		"Socket BGA1023",
		"Socket BGA1224",
		"Socket LGA1155",
		"Socket LGA1356",
		"Socket LGA2011",
		"Socket FS1",
		"Socket FS2",
		"Socket FM1",
		"Socket FM2",
		"Socket LGA2011-3",
		"Socket LGA1356-3",
		"Socket LGA1150",
		"Socket BGA1168",
		"Socket BGA1234",
		"Socket BGA1364",
		"Socket AM4",
		"Socket LGA1151",
		"Socket BGA1356",
		"Socket BGA1440",
		"Socket BGA1515",
		"Socket LGA3647-1",
		"Socket SP3",
		"Socket SP3r2",
	}
	if int(p) >= len(upgrades) {
		return fmt.Sprintf("Unknown_Upgrade_Value_%d", p)
	}
	return upgrades[p]
}

func (p ProcessorUpgrade) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

type ProcessorCharacteristics uint16

var processorCharacteristics = []string{
	"Reserved",
	"Unknown",
	"64-bit Capable",
	"Multi-Core",
	"Hardware Thread",
	"Execute Protection",
	"Enhanced Virtualization",
	"Power/Performance Control",
}

const (
	ProcessorCharacteristicsReserved ProcessorCharacteristics = 1 << iota
	ProcessorCharacteristicsUnknown
	ProcessorCharacteristics64_bitCapable
	ProcessorCharacteristicsMulti_Core
	ProcessorCharacteristicsHardwareThread
	ProcessorCharacteristicsExecuteProtection
	ProcessorCharacteristicsEnhancedVirtualization
	ProcessorCharacteristicsPowerPerformanceControl
)

func (p ProcessorCharacteristics) String() string {
	return strings.Join(p.StringList(), "\n\t\t")
}

func (p ProcessorCharacteristics) StringList() []string {
	var s []string
	for i := uint(0); i < 8; i++ {
		if p&(1<<i) != 0 {
			s = append(s, processorCharacteristics[i])
		}
	}
	return s
}

func (p ProcessorCharacteristics) MarshalJSON() ([]byte, error) {
	buf := map[string]bool{}
	for _, s := range p.StringList() {
		buf[s] = true
	}
	return json.Marshal(&buf)
}

// type 4
type ProcessorInformation struct {
	infoCommon
	SocketDesignation string
	ProcessorType     ProcessorType
	Family            ProcessorFamily
	Manufacturer      string
	ID                ProcessorID
	Version           string
	Voltage           ProcessorVoltage
	ExternalClock     uint16
	MaxSpeed          uint16
	CurrentSpeed      uint16
	Status            ProcessorStatus
	Upgrade           ProcessorUpgrade
	L1CacheHandle     uint16
	L2CacheHandle     uint16
	L3CacheHandle     uint16
	SerialNumber      string
	AssetTag          string
	PartNumber        string
	CoreCount         byte
	CoreEnabled       byte
	ThreadCount       byte
	Characteristics   ProcessorCharacteristics
}

func (p ProcessorInformation) String() string {
	return fmt.Sprintf("Processor Information\n"+
		"\tSocket Designation: %s\n"+
		"\tProcessor Type: %s\n"+
		"\tFamily: %s\n"+
		"\tManufacturer: %s\n"+
		"\tID: %x\n"+
		"\tVersion: %s\n"+
		"\tVoltage: %s\n"+
		"\tExternal Clock: %d MHz\n"+
		"\tMax Speed: %d MHz\n"+
		"\tCurrent Speed: %d MHz\n"+
		"\tStatus: %s\n"+
		"\tUpgrade: %s\n"+
		"\tL1 Cache Handle: %#x\n"+
		"\tL2 Cache Handle: %#x\n"+
		"\tL3 Cache Handle: %#x\n"+
		"\tSerial Number: %s\n"+
		"\tAsset Tag: %s\n"+
		"\tPart Number: %s\n"+
		"\tCore Count: %d\n"+
		"\tCore Enabled: %d\n"+
		"\tThread Count: %d\n"+
		"\tCharacteristics: %s\n",
		p.SocketDesignation,
		p.ProcessorType,
		p.Family,
		p.Manufacturer,
		p.ID,
		p.Version,
		p.Voltage,
		p.ExternalClock,
		p.MaxSpeed,
		p.CurrentSpeed,
		p.Status,
		p.Upgrade,
		p.L1CacheHandle,
		p.L2CacheHandle,
		p.L3CacheHandle,
		p.SerialNumber,
		p.AssetTag,
		p.PartNumber,
		p.CoreCount,
		p.CoreEnabled,
		p.ThreadCount,
		p.Characteristics)
}

func newProcessorInformation(h dmiHeader) dmiTyper {
	data := h.data
	pi := &ProcessorInformation{
		SocketDesignation: h.FieldString(int(data[0x04])),
		ProcessorType:     ProcessorType(data[0x05]),
		Family:            ProcessorFamily(data[0x06]),
		Manufacturer:      h.FieldString(int(data[0x07])),
		// TODO: ID print as 0x little-endian
		ID:              ProcessorID(u64(data[0x08:0x10])),
		Version:         h.FieldString(int(data[0x10])),
		Voltage:         ProcessorVoltage(data[0x11]),
		ExternalClock:   u16(data[0x12:0x14]),
		MaxSpeed:        u16(data[0x14:0x16]),
		CurrentSpeed:    u16(data[0x16:0x18]),
		Status:          ProcessorStatus(data[0x18]),
		Upgrade:         ProcessorUpgrade(data[0x19]),
		L1CacheHandle:   u16(data[0x1A:0x1C]),
		L2CacheHandle:   u16(data[0x1C:0x1E]),
		L3CacheHandle:   u16(data[0x1E:0x20]),
		SerialNumber:    h.FieldString(int(data[0x20])),
		AssetTag:        h.FieldString(int(data[0x21])),
		PartNumber:      h.FieldString(int(data[0x22])),
		CoreCount:       data[0x23],
		CoreEnabled:     data[0x24],
		ThreadCount:     data[0x25],
		Characteristics: ProcessorCharacteristics(u16(data[0x26:0x28])),
	}
	if pi.Family == 0xfe {
		pi.Family = ProcessorFamily(u16(data[0x28:0x2a]))
	}
	ProcessorInformations = append(ProcessorInformations, pi)
	return pi
}

var ProcessorInformations []*ProcessorInformation

func Processor() []*ProcessorInformation {
	return ProcessorInformations
}

func GetProcessorInformation() string {
	var ret string
	for i, v := range ProcessorInformations {
		ret += "\n processor infomation index:" + strconv.Itoa(i) + "\n" + v.String()
	}
	return ret
}

func init() {
	addTypeFunc(SMBIOSStructureTypeProcessor, newProcessorInformation)
}
