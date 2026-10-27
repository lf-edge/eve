// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package cpu

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/zededa/ghw/internal/log"
	"github.com/zededa/ghw/pkg/linuxdt"
	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/memory"
	"github.com/zededa/ghw/pkg/util"
)

var (
	regexForCpulCore = regexp.MustCompile("^cpu([0-9]+)$")
	onlineFile       = "online"
)

func (i *Info) load(ctx context.Context) error {
	online, offline := logicalProcessorIDs(ctx)
	procIDs, coreIDs := topologyOf(ctx, online)
	i.Processors = processorsGet(ctx, online, procIDs, coreIDs)
	var totCores uint32
	var totThreads uint32
	for _, p := range i.Processors {
		totCores += p.TotalCores
		totThreads += p.TotalHardwareThreads
	}
	i.TotalCores = totCores
	i.TotalHardwareThreads = totThreads
	// TODO(jaypipes): Remove TotalThreads before v1.0
	i.TotalThreads = totThreads
	ascending := slices.Clone(online)
	slices.Sort(ascending)
	i.LogicalProcessors = logicalProcessorsGet(ctx, ascending, procIDs, coreIDs)
	i.OfflineLogicalProcessors = offline
	caches, err := memory.Caches(ctx)
	if err != nil {
		log.Warn(ctx, "failed to read CPU caches: %s", err)
	}
	i.Caches = caches
	return nil
}

// logicalProcessorIDs returns the IDs of the online logical processors, in the
// order /sys/devices/system/cpu lists them, and of the offline ones, ascending.
func logicalProcessorIDs(ctx context.Context) (online, offline []int) {
	paths := linuxpath.New(ctx)
	// /sys/devices/system/cpu pseudodir contains N number of pseudodirs with
	// information about the logical processors on the host. These logical
	// processor pseudodirs are of the pattern /sys/devices/system/cpu/cpu{N}
	fnames, err := os.ReadDir(paths.SysDevicesSystemCPU)
	if err != nil {
		log.Warn(ctx, "failed to read /sys/devices/system/cpu: %s", err)
		return nil, nil
	}
	for _, fname := range fnames {
		matches := regexForCpulCore.FindStringSubmatch(fname.Name())
		if len(matches) < 2 {
			continue
		}

		lpID, err := strconv.Atoi(matches[1])
		if err != nil {
			log.Warn(ctx, "failed to find numeric logical processor ID: %s", err)
			continue
		}

		onlineFilePath := filepath.Join(paths.SysDevicesSystemCPU, fmt.Sprintf("cpu%d", lpID), onlineFile)
		if _, err := os.Stat(onlineFilePath); err == nil {
			if util.SafeIntFromFile(ctx, onlineFilePath) == 0 {
				offline = append(offline, lpID)
				continue
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// Assume the CPU is online if the online state file doesn't exist
			// (as is the case with older snapshots)
		}
		online = append(online, lpID)
	}
	sort.Ints(offline)
	return online, offline
}

func processorsGet(ctx context.Context, onlineLPs []int, procIDs, coreIDs map[int]int) []*Processor {
	lps := logicalProcessorsFromProcCPUInfo(ctx)
	// keyed by processor ID (physical_package_id)
	procs := map[int]*Processor{}

	for _, lpID := range onlineLPs {
		procID := procIDs[lpID]
		proc, found := procs[procID]
		if !found {
			proc = &Processor{ID: procID}
			lp, ok := lps[lpID]
			if !ok {
				log.Warn(ctx,
					"failed to find attributes for logical processor %d",
					lpID,
				)
				continue
			}

			// Assumes /proc/cpuinfo is in order of logical processor id, then
			// lps[lpID] describes logical processor `lpID`.
			// Once got a more robust way of fetching the following info,
			// can we drop /proc/cpuinfo.
			// 1. Capabilities (Hardware Features)
			if len(lp.Attrs["flags"]) != 0 { // x86
				proc.Capabilities = strings.Split(lp.Attrs["flags"], " ")
			} else if len(lp.Attrs["Features"]) != 0 { // ARM64
				proc.Capabilities = strings.Split(lp.Attrs["Features"], " ")
			} else if len(lp.Attrs["features"]) != 0 { // s390x
				proc.Capabilities = strings.Split(lp.Attrs["features"], " ")
			}

			// 2. Model Detection
			if len(lp.Attrs["model name"]) != 0 {
				proc.Model = lp.Attrs["model name"]
			} else if len(lp.Attrs["Processor"]) != 0 { // ARM
				proc.Model = lp.Attrs["Processor"]
			} else if len(lp.Attrs["cpu model"]) != 0 { // MIPS, ARM
				proc.Model = lp.Attrs["cpu model"]
			} else if len(lp.Attrs["Model Name"]) != 0 { // LoongArch
				proc.Model = lp.Attrs["Model Name"]
			} else if len(lp.Attrs["uarch"]) != 0 { // SiFive
				proc.Model = lp.Attrs["uarch"]
			} else if len(lp.Attrs["machine"]) != 0 {
				proc.Model = lp.Attrs["machine"]
			}
			// Last resort: many ARM/RISC-V boards expose no useful model in
			// /proc/cpuinfo. Fall back to the DeviceTree SoC compatible, e.g.
			// "rockchip,rk3576".
			if proc.Model == "" && linuxdt.Available(ctx) {
				if soc := linuxdt.SoC(ctx); soc != util.UNKNOWN {
					proc.Model = soc
				}
			}
			// 3. Vendor Detection
			if len(lp.Attrs["vendor_id"]) != 0 {
				proc.Vendor = lp.Attrs["vendor_id"]
			} else if len(lp.Attrs["isa"]) != 0 { // RISCV64
				proc.Vendor = lp.Attrs["isa"]
			} else if lp.Attrs["CPU implementer"] == "0x41" { // ARM
				proc.Vendor = "ARM"
			}
			procs[procID] = proc
		}

		coreID := coreIDs[lpID]
		var core *ProcessorCore
		// An unknown core (-1) is not known to be shared: a core of its own.
		if coreID != -1 {
			core = proc.CoreByID(coreID)
		}
		if core == nil {
			core = &ProcessorCore{
				ID:                   coreID,
				TotalHardwareThreads: 1,
				// TODO(jaypipes): Remove NumThreads before v1.0
				NumThreads: 1,
			}
			proc.Cores = append(proc.Cores, core)
			proc.TotalCores += 1
			// TODO(jaypipes): Remove NumCores before v1.0
			proc.NumCores += 1
		} else {
			core.TotalHardwareThreads += 1
			// TODO(jaypipes) Remove NumThreads before v1.0
			core.NumThreads += 1
		}
		proc.TotalHardwareThreads += 1
		// TODO(jaypipes) Remove NumThreads before v1.0
		proc.NumThreads += 1
		core.LogicalProcessors = append(core.LogicalProcessors, lpID)
	}
	res := []*Processor{}
	for _, p := range procs {
		for _, c := range p.Cores {
			sort.Ints(c.LogicalProcessors)
		}
		res = append(res, p)
	}
	// procs is a map, so the loop above appends in random order; sort so
	// that repeated calls on the same host return the same order.
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return res
}

// coreIDFromLogicalProcessorID returns the core ID for the supplied logical
// processor ID
func coreIDFromLogicalProcessorID(ctx context.Context, lpID int) int {
	paths := linuxpath.New(ctx)
	// Fetch CPU ID
	path := filepath.Join(
		paths.SysDevicesSystemCPU,
		fmt.Sprintf("cpu%d", lpID),
		"topology", "core_id",
	)
	return util.SafeIntFromFile(ctx, path)
}

// topologyOf returns the physical package and the core ID of each of the given
// logical processors, the core ID unique within its package. The kernel's
// core_id is that on x86, but an ARM device tree numbers cores per cluster, so
// core_id repeats within a package for cores that are not SMT siblings. Where
// one core_id covers more than one set of siblings (thread_siblings_list) in a
// package, every core of that package is numbered by the lowest logical
// processor among its siblings instead, and a logical processor whose siblings
// cannot be read gets -1.
func topologyOf(ctx context.Context, lpIDs []int) (procIDs, coreIDs map[int]int) {
	paths := linuxpath.New(ctx)
	type key struct{ proc, core int }
	procIDs = make(map[int]int, len(lpIDs))
	coreIDs = make(map[int]int, len(lpIDs))
	firstSibling := map[int]int{}
	allMinusOne := len(lpIDs) > 0
	for _, lpID := range lpIDs {
		procIDs[lpID] = -1
		pkgPath := filepath.Join(paths.SysDevicesSystemCPU, fmt.Sprintf("cpu%d", lpID),
			"topology", "physical_package_id")
		if pkg, err := util.ReadInt(pkgPath); err != nil {
			log.Warn(ctx, "failed to read the package of logical processor %d: %s", lpID, err)
			allMinusOne = false
		} else {
			procIDs[lpID] = pkg
			allMinusOne = allMinusOne && pkg == -1
		}
		coreIDs[lpID] = coreIDFromLogicalProcessorID(ctx, lpID)
		siblings, err := util.ReadCPUList(filepath.Join(paths.SysDevicesSystemCPU,
			fmt.Sprintf("cpu%d", lpID), "topology", "thread_siblings_list"))
		if err != nil || len(siblings) == 0 {
			continue
		}
		firstSibling[lpID] = slices.Min(siblings)
	}
	// physical_package_id -1 from every CPU is the kernel saying it has no
	// package information: one package. Next to CPUs with a real package it
	// is unknown.
	if allMinusOne {
		for _, lpID := range lpIDs {
			procIDs[lpID] = 0
		}
	}
	// Clusters are found per package, so only once the package IDs are final.
	siblingSets := map[key]map[int]struct{}{}
	for lpID, first := range firstSibling {
		k := key{procIDs[lpID], coreIDs[lpID]}
		if siblingSets[k] == nil {
			siblingSets[k] = map[int]struct{}{}
		}
		siblingSets[k][first] = struct{}{}
	}
	clustered := map[int]bool{}
	for k, sets := range siblingSets {
		if len(sets) > 1 {
			clustered[k.proc] = true
		}
	}
	for _, lpID := range lpIDs {
		if !clustered[procIDs[lpID]] {
			continue
		}
		if first, ok := firstSibling[lpID]; ok {
			coreIDs[lpID] = first
		} else {
			coreIDs[lpID] = -1
		}
	}
	return procIDs, coreIDs
}

func CoresForNode(ctx context.Context, nodeID int) ([]*ProcessorCore, error) {
	// The /sys/devices/system/node/nodeX directory contains a subdirectory
	// called 'cpuX' for each logical processor assigned to the node. Cores are
	// identified as for Info: see topologyOf.
	paths := linuxpath.New(ctx)
	path := filepath.Join(
		paths.SysDevicesSystemNode,
		fmt.Sprintf("node%d", nodeID),
	)

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var lpIDs []int
	for _, file := range files {
		filename := file.Name()
		if !strings.HasPrefix(filename, "cpu") {
			continue
		}
		if filename == "cpumap" || filename == "cpulist" {
			// There are two files in the node directory that start with 'cpu'
			// but are not subdirectories ('cpulist' and 'cpumap'). Ignore
			// these files.
			continue
		}
		// Grab the logical processor ID by cutting the integer from the
		// /sys/devices/system/node/nodeX/cpuX filename
		cpuPath := filepath.Join(path, filename)
		lpID, err := strconv.Atoi(filename[3:])
		if err != nil {
			log.Warn(ctx,
				"failed to determine procID from %s. Expected integer after 3rd char.",
				filename,
			)
			continue
		}
		onlineFilePath := filepath.Join(cpuPath, onlineFile)
		if _, err := os.Stat(onlineFilePath); err == nil {
			if util.SafeIntFromFile(ctx, onlineFilePath) == 0 {
				continue
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// Assume the CPU is online if the online state file doesn't exist
			// (as is the case with older snapshots)
		}
		lpIDs = append(lpIDs, lpID)
	}

	// A node can hold more than one package, so a core is a package and a
	// core ID. Whether a package is clustered depends on all its CPUs, not
	// only the node's, or the node's cores would be numbered unlike Info's.
	online, _ := logicalProcessorIDs(ctx)
	procIDs, coreIDs := topologyOf(ctx, online)
	type key struct{ proc, core int }
	byKey := map[key]*ProcessorCore{}
	cores := make([]*ProcessorCore, 0)
	for _, lpID := range lpIDs {
		k := key{procIDs[lpID], coreIDs[lpID]}
		core, ok := byKey[k]
		if !ok {
			core = &ProcessorCore{
				ID:                k.core,
				LogicalProcessors: []int{},
			}
			// As in Info, an unknown core is a core of its own.
			if k.core != -1 {
				byKey[k] = core
			}
			cores = append(cores, core)
		}
		core.LogicalProcessors = append(core.LogicalProcessors, lpID)
	}

	for _, c := range cores {
		c.TotalHardwareThreads = uint32(len(c.LogicalProcessors))
		// TODO(jaypipes): Remove NumThreads before v1.0
		c.NumThreads = c.TotalHardwareThreads
	}

	return cores, nil
}

// logicalProcessor contains information about a single logical processor
// on the host.
type logicalProcessor struct {
	// This is the logical processor ID assigned by the host. In /proc/cpuinfo,
	// this is the zero-based index of the logical processor as it appears in
	// the /proc/cpuinfo file and matches the "processor" attribute. In
	// /sys/devices/system/cpu/cpu{N} pseudodir entries, this is the N value.
	ID int
	// The entire collection of string attribute name/value pairs for the
	// logical processor.
	Attrs map[string]string
}

// logicalProcessorsFromProcCPUInfo reads the `/proc/cpuinfo` pseudofile and
// returns a map, keyed by logical processor ID, of logical processor structs.
//
// `/proc/cpuinfo` files look like the following:
//
// ```
// processor	: 0
// vendor_id	: AuthenticAMD
// cpu family	: 23
// model		: 8
// model name	: AMD Ryzen 7 2700X Eight-Core Processor
// stepping	: 2
// microcode	: 0x800820d
// cpu MHz		: 2200.000
// cache size	: 512 KB
// physical id	: 0
// siblings	: 16
// core id		: 0
// cpu cores	: 8
// apicid		: 0
// initial apicid	: 0
// fpu		: yes
// fpu_exception	: yes
// cpuid level	: 13
// wp		: yes
// flags		: fpu vme de pse tsc msr pae mce <snip...>
// bugs		: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass retbleed smt_rsb
// bogomips	: 7386.41
// TLB size	: 2560 4K pages
// clflush size	: 64
// cache_alignment	: 64
// address sizes	: 43 bits physical, 48 bits virtual
// power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]
//
// processor	: 1
// vendor_id	: AuthenticAMD
// cpu family	: 23
// model		: 8
// model name	: AMD Ryzen 7 2700X Eight-Core Processor
// stepping	: 2
// microcode	: 0x800820d
// cpu MHz		: 1885.364
// cache size	: 512 KB
// physical id	: 0
// siblings	: 16
// core id		: 1
// cpu cores	: 8
// apicid		: 2
// initial apicid	: 2
// fpu		: yes
// fpu_exception	: yes
// cpuid level	: 13
// wp		: yes
// flags		: fpu vme de pse tsc msr pae mce <snip...>
// bugs		: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass retbleed smt_rsb
// bogomips	: 7386.41
// TLB size	: 2560 4K pages
// clflush size	: 64
// cache_alignment	: 64
// address sizes	: 43 bits physical, 48 bits virtual
// power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]
// ```
//
// with blank line-separated blocks of colon-delimited attribute name/value
// pairs for a specific logical processor on the host.
func logicalProcessorsFromProcCPUInfo(
	ctx context.Context,
) map[int]*logicalProcessor {
	paths := linuxpath.New(ctx)
	r, err := os.Open(paths.ProcCpuinfo)
	if err != nil {
		return nil
	}
	defer util.SafeClose(r)

	lps := map[int]*logicalProcessor{}

	// A map of attributes describing the logical processor
	lpAttrs := map[string]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			// Output of /proc/cpuinfo has a blank newline to separate logical
			// processors, so here we collect up all the attributes we've
			// collected for this logical processor block
			// s390x identifies CPUs via "cpu number", while most other
			// architectures use "processor".
			idStr, ok := lpAttrs["processor"]
			if !ok {
				idStr, ok = lpAttrs["cpu number"]
			}

			if ok {
				id, _ := strconv.Atoi(idStr)
				lps[id] = &logicalProcessor{
					ID:    id,
					Attrs: lpAttrs,
				}
				// Only reset attributes after a valid processor block is saved.
				// This ensures that shared header metadata (like vendor_id on s390x)
				// is carried over and available to the processor entries.
				lpAttrs = map[string]string{}
			} else if len(lpAttrs) > 0 {
				// s390x header check: if we have 'vendor_id' but no 'processor' ID,
				// it's the summary block. We don't warn and we don't reset lpAttrs
				// so the vendor_id carries over to the first actual CPU block.
				if _, isS390Header := lpAttrs["vendor_id"]; !isS390Header {
					log.Warn(ctx,
						"expected to find 'processor' or 'cpu number' key "+
							"in /proc/cpuinfo attributes")
				}
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) >= 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			lpAttrs[key] = value
		}
	}
	return lps
}

// logicalProcessorsGet describes each of the given online logical processors.
func logicalProcessorsGet(ctx context.Context, lpIDs []int, procIDs, coreIDs map[int]int) []*LogicalProcessor {
	paths := linuxpath.New(ctx)
	nodeOf := nodesOf(ctx)
	types := coreTypesOf(ctx, lpIDs)
	lps := make([]*LogicalProcessor, 0, len(lpIDs))
	for _, id := range lpIDs {
		dir := filepath.Join(paths.SysDevicesSystemCPU, fmt.Sprintf("cpu%d", id))
		lp := &LogicalProcessor{
			ID:          id,
			ProcessorID: procIDs[id],
			CoreID:      coreIDs[id],
			NodeID:      -1,
			CoreType:    types[id],
		}
		// A frequency the kernel does not report stays 0.
		if khz, err := util.ReadInt(filepath.Join(dir, "cpufreq", "base_frequency")); err == nil && khz > 0 {
			lp.BaseFrequencyKHz = uint64(khz)
		}
		if khz, err := util.ReadInt(filepath.Join(dir, "cpufreq", "cpuinfo_max_freq")); err == nil && khz > 0 {
			lp.MaxFrequencyKHz = uint64(khz)
		}
		if nodeOf == nil {
			lp.NodeID = 0
		} else if node, ok := nodeOf[id]; ok {
			lp.NodeID = node
		}
		lps = append(lps, lp)
	}
	return lps
}

// nodesOf maps each logical processor to its NUMA node, from the nodes'
// cpulist files. It is nil when the kernel has no NUMA support (no node
// directory); a logical processor no node lists is missing from the map.
func nodesOf(ctx context.Context) map[int]int {
	paths := linuxpath.New(ctx)
	entries, err := os.ReadDir(paths.SysDevicesSystemNode)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn(ctx, "failed to read %s: %s", paths.SysDevicesSystemNode, err)
			return map[int]int{}
		}
		return nil
	}
	nodeOf := map[int]int{}
	for _, entry := range entries {
		node, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "node"))
		if err != nil || !strings.HasPrefix(entry.Name(), "node") {
			continue
		}
		cpus, err := util.ReadCPUList(filepath.Join(paths.SysDevicesSystemNode, entry.Name(), "cpulist"))
		if err != nil {
			log.Warn(ctx, "failed to read the CPUs of NUMA node %d: %s", node, err)
			continue
		}
		for _, cpu := range cpus {
			nodeOf[cpu] = node
		}
	}
	return nodeOf
}

// coreTypesOf tells each logical processor's core type. Intel hybrid parts list
// their performance cores under the cpu_core PMU and their efficiency cores
// under cpu_atom and, for the low-power ones, cpu_lowpower. Elsewhere, ARM
// big.LITTLE among them, cpu_capacity ranks the logical processors: the highest
// capacity is a performance core, any lower an efficiency core, and one
// capacity for all of them a homogeneous part (x86 reports 1024 for every CPU
// of a homogeneous part since Linux 6.16). Before that, a homogeneous x86 part
// is told by its single core PMU, /sys/devices/cpu. When none of these tells,
// or only some CPUs report a capacity, the type is unknown, never guessed.
//
// The ranking sees only the online CPUs: with every big core offline, the
// LITTLE ones read as performance or uniform. And it ranks by capacity alone,
// so on a part with three classes of core (prime, big, LITTLE) the middle one
// reads as efficiency.
func coreTypesOf(ctx context.Context, lpIDs []int) map[int]CoreType {
	paths := linuxpath.New(ctx)
	devices := filepath.Join(paths.SysRoot, "devices")
	types := map[int]CoreType{}

	var hybrid bool
	for pmu, coreType := range map[string]CoreType{
		"cpu_core":     CoreTypePerformance,
		"cpu_atom":     CoreTypeEfficiency,
		"cpu_lowpower": CoreTypeEfficiency,
	} {
		cpus, err := util.ReadCPUList(filepath.Join(devices, pmu, "cpus"))
		if err != nil {
			continue
		}
		hybrid = true
		for _, id := range cpus {
			types[id] = coreType
		}
	}
	if hybrid {
		return types
	}

	capacities := map[int]int{}
	for _, id := range lpIDs {
		capacity, err := util.ReadInt(filepath.Join(paths.SysDevicesSystemCPU, fmt.Sprintf("cpu%d", id), "cpu_capacity"))
		if err == nil {
			capacities[id] = capacity
		}
	}
	if len(capacities) > 0 && len(capacities) < len(lpIDs) {
		return types
	}
	if len(capacities) > 0 {
		lowest, highest := math.MaxInt, math.MinInt
		for _, capacity := range capacities {
			lowest, highest = min(lowest, capacity), max(highest, capacity)
		}
		for id, capacity := range capacities {
			switch {
			case lowest == highest:
				types[id] = CoreTypeUniform
			case capacity == highest:
				types[id] = CoreTypePerformance
			default:
				types[id] = CoreTypeEfficiency
			}
		}
		return types
	}

	if fi, err := os.Stat(filepath.Join(devices, "cpu")); err == nil && fi.IsDir() {
		for _, id := range lpIDs {
			types[id] = CoreTypeUniform
		}
	}
	return types
}
