//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package cpu

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zededa/ghw/internal/config"
	"github.com/zededa/ghw/pkg/marshal"
	"github.com/zededa/ghw/pkg/memory"
)

// ProcessorCore describes a physical host processor core. A processor core is
// a separate processing unit within some types of central processing units
// (CPU).
type ProcessorCore struct {
	// ID is the `uint32` identifier that the host gave this core. Note that
	// this does *not* necessarily equate to a zero-based index of the core
	// within a physical package. For example, the core IDs for an Intel Core
	// i7 are 0, 1, 2, 8, 9, and 10. It is -1 where the core cannot be told;
	// each such core holds a single logical processor.
	ID int `json:"id"`
	// TotalHardwareThreads is the number of hardware threads associated with
	// the core
	TotalHardwareThreads uint32 `json:"total_hardware_threads"`
	// NumThreads is the number of hardware threads associated with the core.
	// DEPRECATED: Use `TotalHardwareThreads` instead.
	NumThreads uint32 `json:"total_threads"`
	// LogicalProcessors is a slice of ints representing the logical processor
	// IDs assigned to any processing unit for the core. These are sometimes
	// called the "thread siblings". Logical processor IDs are the *zero-based*
	// index of the processor on the host and are *not* related to the core ID.
	LogicalProcessors []int `json:"logical_processors"`
}

// String returns a short string indicating important information about the
// processor core
func (c *ProcessorCore) String() string {
	return fmt.Sprintf(
		"processor core #%d (%d threads), logical processors %v",
		c.ID,
		c.TotalHardwareThreads,
		c.LogicalProcessors,
	)
}

// Processor describes a physical host central processing unit (CPU).
type Processor struct {
	// ID is the physical processor `uint32` ID according to the system
	ID int `json:"id"`
	// TotalCores is the number of physical cores in the processor package
	TotalCores uint32 `json:"total_cores"`
	// NumCores is the number of physical cores in the processor package
	// DEPRECATED: Use `TotalCores` instead.
	NumCores uint32 `json:"-"`
	// TotalHardwareThreads is the number of hardware threads associated with
	// the processor package
	TotalHardwareThreads uint32 `json:"total_hardware_threads"`
	// NumThreads is the number of hardware threads in the processor package
	// DEPRECATED: Use `TotalHardwareThreads` instead.
	NumThreads uint32 `json:"total_threads"`
	// Vendor is a string containing the vendor name
	Vendor string `json:"vendor"`
	// Model` is a string containing the vendor's model name
	Model string `json:"model"`
	// Capabilities is a slice of strings indicating the features the processor
	// has enabled
	Capabilities []string `json:"capabilities"`
	// Cores is a slice of ProcessorCore` struct pointers that are packed onto
	// this physical processor
	Cores []*ProcessorCore `json:"cores"`
}

// CoreByID returns the ProcessorCore having the supplied ID.
func (p *Processor) CoreByID(coreID int) *ProcessorCore {
	for _, core := range p.Cores {
		if core.ID == coreID {
			return core
		}
	}
	return nil
}

// HasCapability returns true if the Processor has the supplied cpuid
// capability, false otherwise. Example of cpuid capabilities would be 'vmx' or
// 'sse4_2'. To see a list of potential cpuid capabilitiies, see the section on
// CPUID feature bits in the following article:
//
// https://en.wikipedia.org/wiki/CPUID
func (p *Processor) HasCapability(find string) bool {
	for _, c := range p.Capabilities {
		if c == find {
			return true
		}
	}
	return false
}

// String returns a short string describing the Processor
func (p *Processor) String() string {
	ncs := "cores"
	if p.TotalCores == 1 {
		ncs = "core"
	}
	nts := "threads"
	if p.TotalHardwareThreads == 1 {
		nts = "thread"
	}
	return fmt.Sprintf(
		"physical package #%d (%d %s, %d hardware %s)",
		p.ID,
		p.TotalCores,
		ncs,
		p.TotalHardwareThreads,
		nts,
	)
}

// Info describes all central processing unit (CPU) functionality on a host.
// Returned by the `ghw.CPU()` function.
type Info struct {
	// TotalCores is the total number of physical cores the host system
	// contains
	TotalCores uint32 `json:"total_cores"`
	// TotalThreads is the total number of hardware threads the host system
	// contains
	TotalHardwareThreads uint32 `json:"total_hardware_threads"`
	// TotalThreads is the total number of hardware threads the host system
	// contains
	// DEPRECATED: Use `TotalHardwareThreads` instead
	TotalThreads uint32 `json:"total_threads"`
	// Processors is a slice of Processor struct pointers, one for each
	// physical processor package contained in the host
	Processors []*Processor `json:"processors"`
	// LogicalProcessors describes each online logical processor, ascending by
	// ID.
	LogicalProcessors []*LogicalProcessor `json:"logical_processors,omitempty"`
	// OfflineLogicalProcessors are the IDs of the logical processors that are
	// present but offline (for example SMT turned off), ascending.
	OfflineLogicalProcessors []int `json:"offline_logical_processors,omitempty"`
	// Caches lists every cache instance of the online logical processors,
	// with the logical processors sharing it.
	Caches []*memory.Cache `json:"caches,omitempty"`
}

// LogicalProcessor describes one online logical processor (hardware thread)
// and where it sits in the host's topology. An ID that could not be read is -1,
// and a frequency the kernel does not report is 0.
type LogicalProcessor struct {
	// ID is the logical processor ID the kernel and CPU affinities use.
	ID int `json:"id"`
	// ProcessorID is the physical package (socket) it belongs to, the ID of
	// its Processor in Processors (unless /proc/cpuinfo does not describe the
	// logical processor, which leaves it out of Processors).
	ProcessorID int `json:"processor_id"`
	// CoreID is the physical core it runs on, the ID of its ProcessorCore,
	// unique within the package. Logical processors with the same known
	// ProcessorID and CoreID are SMT siblings; two with an ID of -1 are not
	// known to be.
	CoreID int `json:"core_id"`
	// NodeID is the NUMA node it belongs to; 0 on a kernel without NUMA.
	NodeID int `json:"node_id"`
	// CoreType is the class of core it runs on.
	CoreType CoreType `json:"core_type"`
	// BaseFrequencyKHz is its base (non-turbo) frequency.
	BaseFrequencyKHz uint64 `json:"base_frequency_khz,omitempty"`
	// MaxFrequencyKHz is its maximum (turbo) frequency.
	MaxFrequencyKHz uint64 `json:"max_frequency_khz,omitempty"`
}

// New returns a pointer to an Info struct that contains information about the
// CPUs on the host system
func New(args ...any) (*Info, error) {
	ctx := config.ContextFromArgs(args...)
	info := &Info{}
	if err := info.load(ctx); err != nil {
		return nil, err
	}
	return info, nil
}

// String returns a short string indicating a summary of CPU information
func (i *Info) String() string {
	nps := "packages"
	if len(i.Processors) == 1 {
		nps = "package"
	}
	ncs := "cores"
	if i.TotalCores == 1 {
		ncs = "core"
	}
	nts := "threads"
	if i.TotalThreads == 1 {
		nts = "thread"
	}
	return fmt.Sprintf(
		"cpu (%d physical %s, %d %s, %d hardware %s)",
		len(i.Processors),
		nps,
		i.TotalCores,
		ncs,
		i.TotalThreads,
		nts,
	)
}

// simple private struct used to encapsulate cpu information in a top-level
// "cpu" YAML/JSON map/object key
type cpuPrinter struct {
	Info *Info `json:"cpu"`
}

// YAMLString returns a string with the cpu information formatted as YAML
// under a top-level "cpu:" key
func (i *Info) YAMLString() string {
	return marshal.SafeYAML(cpuPrinter{i})
}

// JSONString returns a string with the cpu information formatted as JSON
// under a top-level "cpu:" key
func (i *Info) JSONString(indent bool) string {
	return marshal.SafeJSON(cpuPrinter{i}, indent)
}

// CoreType is the class of core a logical processor runs on.
type CoreType int

const (
	// CoreTypeUnknown means the host does not tell the class of the core.
	CoreTypeUnknown CoreType = iota
	// CoreTypePerformance is a performance core of a heterogeneous part, such
	// as an Intel P-core or an ARM "big" core.
	CoreTypePerformance
	// CoreTypeEfficiency is an efficiency core of a heterogeneous part, such
	// as an Intel E-core or an ARM "LITTLE" core.
	CoreTypeEfficiency
	// CoreTypeUniform is a core of a homogeneous part, where every core is of
	// the same class.
	CoreTypeUniform
)

var (
	coreTypeString = map[CoreType]string{
		CoreTypeUnknown:     "unknown",
		CoreTypePerformance: "performance",
		CoreTypeEfficiency:  "efficiency",
		CoreTypeUniform:     "uniform",
	}
	stringCoreType = map[string]CoreType{
		"unknown":     CoreTypeUnknown,
		"performance": CoreTypePerformance,
		"efficiency":  CoreTypeEfficiency,
		"uniform":     CoreTypeUniform,
	}
)

// String returns the core type's name, as it appears in JSON and YAML.
func (t CoreType) String() string {
	return coreTypeString[t]
}

// MarshalJSON writes the core type as its name.
func (t CoreType) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(t.String())), nil
}

// UnmarshalJSON reads a core type from its name.
func (t *CoreType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	val, ok := stringCoreType[strings.ToLower(s)]
	if !ok {
		return fmt.Errorf("unknown core type: %q", s)
	}
	*t = val
	return nil
}
