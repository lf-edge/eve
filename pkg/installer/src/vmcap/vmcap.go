// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// For more information check out https://man7.org/linux/man-pages/man4/msr.4.html
// and the Intel document on https://cdrdv2.intel.com/v1/dl/getContent/671200
// (Sections 25.6.x on page 3954 and Appending A -VMX capability reporting facility,
// on page 4488. Please note that the information about pages and sections is based
// on the version of the document on 2024/02/15.)

const (
	basic             = 0x480
	pinBasedCtls      = 0x481
	procBasedCtls     = 0x482
	exitCtls          = 0x483
	entryCtls         = 0x484
	miscCtls          = 0x485
	procBasedCtls2    = 0x48B
	eptVPIDCap        = 0x48C
	truePinBasedCtls  = 0x48D
	trueProcBasedCtls = 0x48E
	trueExitCtls      = 0x48F
	trueEntryCtls     = 0x490
	vmFunc            = 0x491
	procBasedCtls3    = 0x492
)

type msr struct {
	f *os.File
}

func newMsr() (*msr, error) {
	f, err := os.OpenFile("/dev/cpu/0/msr", os.O_RDONLY, 0)
	if err != nil {
		f, err = os.OpenFile("/dev/msr0", os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
	}
	return &msr{f: f}, nil
}

func (m *msr) closeMsrFile() {
	m.f.Close()
}

func (m *msr) read(index uint64, defaultVal uint64) (uint64, error) {
	p := make([]byte, 8)
	_, err := m.f.Seek(int64(index), 0)
	if err != nil {
		return defaultVal, err
	}
	_, err = m.f.Read(p)
	if err != nil {
		return defaultVal, err
	}

	data := binary.LittleEndian.Uint64(p)

	return data, nil
}

type control struct {
	name    string
	bits    map[int]string
	msr     uint64
	trueMsr uint64
}

func (c *control) read(nr uint64) (uint32, uint32, error) {
	m, err := newMsr()
	if err != nil {
		return 0, 0, err
	}
	defer m.closeMsrFile()
	val, _ := m.read(nr, 0)
	return uint32(val & 0xffffffff), uint32(val >> 32), err
}

func (c *control) show() {
	fmt.Println(c.name)
	mb1, cb1, err := c.read(c.msr)
	tmb1, tcb1 := uint32(0), uint32(0)
	if c.trueMsr != 0 {
		tmb1, tcb1, err = c.read(c.trueMsr)
	}
	if err != nil {
		fmt.Println("Cannot read msr registers")
		os.Exit(1)
	}
	for bit := range c.bits {
		zero := !(mb1&(1<<bit) != 0)
		one := cb1&(1<<bit) != 0
		trueZero := !(tmb1&(1<<bit) != 0)
		trueOne := tcb1&(1<<bit) != 0
		s := "?"
		if c.trueMsr != 0 && trueZero && trueOne && one && !zero {
			s = "default"
		} else if zero && !one {
			s = "no"
		} else if one && !zero {
			s = "forced"
		} else if one && zero {
			s = "yes"
		}
		fmt.Printf("  %-60s %s\n", c.bits[bit], s)
	}
}

type allowedControl struct {
	*control
}

func (a *allowedControl) read(nr uint64) (int, uint64, error) {
	m, err := newMsr()
	if err != nil {
		return 0, 0, err
	}
	defer m.closeMsrFile()
	val, _ := m.read(nr, 0)
	return 0, val, err
}

type misc struct {
	name string
	bits map[string]string
	msr  uint64
}

func (m *misc) show() {
	fmt.Println(m.name)
	mymsr, err := newMsr()
	if err != nil {
		fmt.Println("Cannot read msr registers")
		os.Exit(1)
	}
	defer mymsr.closeMsrFile()
	value, _ := mymsr.read(m.msr, 0)
	fmt.Printf("  Hex: 0x%x\n", value)

	for bits, name := range m.bits {
		var low, high int
		arr := strings.Split(bits, ",")
		if len(arr) == 1 {
			low, _ = strconv.Atoi(arr[0])
			high, _ = strconv.Atoi(arr[0])
		} else {
			low, _ = strconv.Atoi(arr[0])
			high, _ = strconv.Atoi(arr[1])
		}

		v := (value >> low) & ((1 << (high - low + 1)) - 1)
		var out string
		if v == 0 {
			out = "no"
		} else if v == 1 {
			out = "yes"
		} else {
			out = strconv.FormatUint(v, 10)
		}
		fmt.Printf("  %-60s %s\n", name, out)
	}
}

func main() {
	controls := []interface{}{
		misc{
			name: "Basic VMX Information",
			bits: map[string]string{
				"0,30":  "VMCS revision identifier used by the processor",
				"32,44": "Allocated size for VMXON and VMCS regions",
				"48":    "Physical address width of VMXON region, etc",
				"49":    "Dual-monitor system management support",
				"50,53": "Memory type for VMCS and data structures",
				"54":    "VM-exit information due to INS/OUTS instructions",
				"55":    "VMX capability for all IA32_VMX_TRUE controls",
				"56":    "VM entry for hardware exception with or without error code",
			},
			msr: basic,
		},
		control{
			name: "Pin-based VM-Execution controls",
			bits: map[int]string{
				0: "External-interrupt exiting",
				3: "NMI exiting",
				5: "Virtual NMIs",
				6: "Activate VMX-preemption timer",
				7: "Process posted interrupts",
			},
			msr:     pinBasedCtls,
			trueMsr: truePinBasedCtls,
		},
		control{
			name: "Primary processor-based VM-Execution controls",
			bits: map[int]string{
				2:  "Interrupt-window exiting",
				3:  "Use TSC offsetting",
				7:  "HLT exiting",
				9:  "INVLPG exiting",
				10: "MWAIT exiting",
				11: "RDPMC exiting",
				12: "RDTSC exiting",
				15: "CR3-load exiting",
				16: "CR3-store exiting",
				17: "Activate tertiary controls",
				19: "CR8-load exiting",
				20: "CR8-store exiting",
				21: "Use TPR shadow",
				22: "NMI-window exiting",
				23: "MOV-DR exiting",
				24: "Unconditional I/O exiting",
				25: "Use I/O bitmaps",
				27: "Monitor trap flag",
				28: "Use MSR bitmaps",
				29: "MONITOR exiting",
				30: "PAUSE exiting",
				31: "Activate secondary controls",
			},
			msr:     procBasedCtls,
			trueMsr: trueProcBasedCtls,
		},
		control{
			name: "Secondary processor-based VM-Execution controls",
			bits: map[int]string{
				0:  "Virtualize APIC accesses",
				1:  "Enable EPT",
				2:  "Descriptor-table exiting",
				3:  "Enable RDTSCP",
				4:  "Virtualize x2APIC mode",
				5:  "Enable VPID",
				6:  "WBINVD exiting",
				7:  "Unrestricted guest",
				8:  "APIC-register virtualization",
				9:  "Virtual-interrupt delivery",
				10: "PAUSE-loop exiting",
				11: "RDRAND exiting",
				12: "Enable INVPCID",
				13: "Enable VM functions",
				14: "VMCS shadowing",
				15: "Enable ENCLS exiting",
				16: "RDSEED exiting",
				17: "Enable PML",
				18: "EPT-violation #VE",
				19: "Conceal VMX from PT",
				20: "Enable XSAVES/XRSTORS",
				21: "PASID translation",
				22: "Mode-based execute control for EPT",
				23: "Sub-page write permissions for EPT",
				24: "Intel PT uses guest physical addresses",
				25: "Use TSC scaling",
				26: "Enable user wait and pause",
				27: "Enable PCONFIG",
				28: "Enable ENCLV exiting",
				30: "VMM bus-lock detection",
				31: "Instruction timeout",
			},
			msr: procBasedCtls2,
		},

		allowedControl{
			control: &control{
				name: "Tertiary processor-based VM-Execution controls",
				bits: map[int]string{
					0: "LOADIWKEY exiting",
					1: "Enable HLAT",
					2: "EPT paging-write control",
					3: "Guest-paging verification",
					4: "IPI virtualization",
					7: "Virtualize IA32_SPEC_CTRL",
				},
				msr: procBasedCtls3,
			},
		},

		control{
			name: "Primary VM-Exit controls",
			bits: map[int]string{
				2:  "Save debug controls",
				9:  "Host address-space size",
				12: "Load IA32_PERF_GLOBAL_CTRL",
				15: "Acknowledge interrupt on exit",
				18: "Save IA32_PAT",
				19: "Load IA32_PAT",
				20: "Save IA32_EFER",
				21: "Load IA32_EFER",
				22: "Save VMX-preemption timer value",
				23: "Clear IA32_BNDCFGS",
				24: "Conceal VMX from PT",
				25: "Clear IA32_RTIT_CTL",
				26: "Clear IA32_LBR_CTL",
				27: "Clear UINV",
				28: "Load CET state",
				29: "Load PKRS",
				30: "Save IA32_PERF_GLOBAL_CTL",
				31: "Activate secondary controls",
			},
			msr:     exitCtls,
			trueMsr: trueExitCtls,
		},

		control{
			name: "VM-Entry controls",
			bits: map[int]string{
				2:  "Load debug controls",
				9:  "IA-32e mode guest",
				10: "Entry to SMM",
				11: "Deactivate dual-monitor treatment",
				13: "Load IA32_PERF_GLOBAL_CTRL",
				14: "Load IA32_PAT",
				15: "Load IA32_EFER",
				16: "Load IA32_BNDCFGS",
				17: "Conceal VMX from PT",
				18: "Load IA32_RTIT_CTL",
				19: "Load UINV",
				20: "Load CET state",
				21: "Load guest IA32_LBR_CTL",
				22: "Load PKRS",
			},
			msr:     entryCtls,
			trueMsr: trueEntryCtls,
		},

		misc{
			name: "Miscellaneous data",
			bits: map[string]string{
				"0,4":   "VMX-preemption timer in relation to timestamp counter",
				"5":     "Store EFER.LMA value into IA-32e mode guest",
				"6":     "HLT activity state support",
				"7":     "shutdown activity state support",
				"8":     "wait-for-SIPI activity state support",
				"14":    "Intel PT in VMX operation",
				"15":    "RDMSR instruction in system-management mode (SMM)",
				"16,24": "Number of CR3-target values supported",
				"25,27": "Recommended maximum number of MSR-load/store",
				"28":    "IA32_SMM_MONITOR_CTL[2] can be set to 1",
				"29":    "VMWRITE for writing supported VMCS fields",
				"30":    "Injection of events with instruction length of 0",
				"32,63": "MSEG revision identifier used by the processor",
			},
			msr: miscCtls,
		},

		misc{
			name: "VPID and EPT capabilities",
			bits: map[string]string{
				"0":     "Support for execute-only translations by EPT",
				"6":     "Support for page-walk length of 4",
				"7":     "Support for page-walk length of 5",
				"8":     "Support for EPT paging-structure memory type uncacheable",
				"14":    "Support for EPT paging-structure memory type write-back",
				"16":    "Support for EPT PDE to map a 2MB page",
				"17":    "Support for EPT PDPTE to map a 1GB page",
				"20":    "INVEPT instruction supported",
				"21":    "Accessed and dirty flags for EPT supported",
				"22":    "Reports of advanced VM-exit information for EPT violations",
				"23":    "Supervisor shadow-stack control supported",
				"25":    "Single-context INVEPT type supported",
				"26":    "All-context INVEPT type supported",
				"32":    "INVVPID instruction supported",
				"40":    "Individual-address INVVPID type supported",
				"41":    "Single-context INVVPID type supported",
				"42":    "All-context INVVPID type supported",
				"43":    "Single-context-retaining-globals INVVPID type supported",
				"48,53": "Maximum HLAT prefix size",
			},
			msr: eptVPIDCap,
		},
		misc{
			name: "VM Functions",
			bits: map[string]string{
				"0": "EPTP Switching",
			},
			msr: vmFunc,
		},
	}

	for _, c := range controls {
		cc, ok := c.(control)
		if ok {
			cc.show()
		}
		cm, ok := c.(misc)
		if ok {
			cm.show()
		}
		ca, ok := c.(allowedControl)
		if ok {
			ca.show()
		}
		fmt.Println()
	}
}
