// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
)

// This file reads the CPU facts the hardware inventory reports beyond the
// topology coordinates that pkg/pillar/cputopology already discovers: cache
// domains, per-CPU frequency, and the kernel's effective CPU-isolation sets.
//
// sysfsRoot is a var so tests can point these readers at a fixture tree.
var sysfsRoot = "/sys/devices/system"

// cacheDomain is one cache instance and the logical CPUs sharing it.
type cacheDomain struct {
	// Level is the cache level as reported by sysfs (1, 2, 3, ...).
	Level int
	// Type is the sysfs cache type: "Data", "Instruction" or "Unified". It is
	// part of a cache's identity because sysfs numbers ids per level, not per
	// type - see readCacheDomains. Empty when sysfs omits the type file.
	Type string
	// ID is the platform's identifier for this cache instance. Caches of the
	// same level and type with the same id are one cache.
	ID uint32
	// SizeBytes is 0 when sysfs does not report a size.
	SizeBytes uint64
	// CPUs are the logical CPUs sharing this cache instance, ascending.
	CPUs []uint32
}

// cacheIDsByCPU maps each CPU to the id of the cache it uses at level. The ids
// come from the same domains the inventory lists, so a CPU's id names the
// CacheDomain that contains it. A level split into data and instruction caches
// is named by its data cache.
func cacheIDsByCPU(domains []cacheDomain, level int) map[uint32]uint32 {
	ids := map[uint32]uint32{}
	for _, d := range domains {
		if d.Level != level || d.Type == "Instruction" {
			continue
		}
		for _, cpu := range d.CPUs {
			ids[cpu] = d.ID
		}
	}
	return ids
}

// readCacheDomains returns the distinct cache instances of the machine.
//
// Each CPU lists the caches it uses; instances are keyed by (level, type, id) so
// the per-CPU views collapse into one entry per real cache with the full set of
// CPUs that share it. That sharing is the point: it is what tells a consumer
// which workloads would contend for the same cache. sysfs numbers cache ids per
// level and not per type, so the L1 data and L1 instruction caches of one core
// are both "level 1, id N" and only the type file separates them - dropping the
// type from the key merges them into one bogus domain listing every CPU twice.
// Every level is reported; the caller decides which matter.
func readCacheDomains() []cacheDomain {
	cpuDirs, err := filepath.Glob(filepath.Join(sysfsRoot, "cpu", "cpu[0-9]*"))
	if err != nil || len(cpuDirs) == 0 {
		return nil
	}

	type key struct {
		level     int
		cacheType string
		id        uint32
	}
	domains := map[key]*cacheDomain{}
	var order []key

	for _, cpuDir := range cpuDirs {
		cpu, err := strconv.ParseUint(
			strings.TrimPrefix(filepath.Base(cpuDir), "cpu"), 10, 32)
		if err != nil {
			continue
		}
		indexDirs, err := filepath.Glob(filepath.Join(cpuDir, "cache", "index[0-9]*"))
		if err != nil {
			continue
		}
		for _, indexDir := range indexDirs {
			level, ok := readUintFile(filepath.Join(indexDir, "level"))
			if !ok {
				continue
			}
			cacheType := readTextFile(filepath.Join(indexDir, "type"))
			id, ok := readUintFile(filepath.Join(indexDir, "id"))
			if !ok {
				// Some platforms omit the id; fall back to the shared-CPU list
				// as the identity by using the lowest CPU in it.
				shared, _ := readCPUList(filepath.Join(indexDir, "shared_cpu_list"))
				if len(shared) == 0 {
					continue
				}
				id = uint64(shared[0])
			}
			k := key{level: int(level), cacheType: cacheType, id: uint32(id)}
			domain, seen := domains[k]
			if !seen {
				size, _ := readCacheSize(filepath.Join(indexDir, "size"))
				domain = &cacheDomain{
					Level:     int(level),
					Type:      cacheType,
					ID:        uint32(id),
					SizeBytes: size,
				}
				domains[k] = domain
				order = append(order, k)
			}
			domain.CPUs = append(domain.CPUs, uint32(cpu))
		}
	}

	result := make([]cacheDomain, 0, len(order))
	for _, k := range order {
		domain := domains[k]
		slices.Sort(domain.CPUs)
		result = append(result, *domain)
	}
	return result
}

// cpuFrequencies returns a logical CPU's base and maximum frequency in kHz.
// Either is 0 when the kernel does not report it, which is normal on platforms
// without cpufreq.
func cpuFrequencies(cpu uint32) (baseKHz, maxKHz uint64) {
	dir := filepath.Join(sysfsRoot, "cpu", "cpu"+strconv.FormatUint(uint64(cpu), 10), "cpufreq")
	// base_frequency is the non-turbo nominal frequency and is the honest
	// answer for "how fast is this CPU"; cpuinfo_max_freq includes turbo.
	if value, ok := readUintFile(filepath.Join(dir, "base_frequency")); ok {
		baseKHz = value
	}
	if value, ok := readUintFile(filepath.Join(dir, "cpuinfo_max_freq")); ok {
		maxKHz = value
	}
	return baseKHz, maxKHz
}

// IsolatedCPUSets returns the CPU sets the running kernel is treating specially.
// These are read from sysfs rather than parsed out of the kernel command line so
// they describe what the kernel is actually doing, which is what a consumer
// deciding where to place a latency-sensitive workload needs. The kernel has no
// sysfs file for rcu_nocbs, so that set is not reported.
func IsolatedCPUSets() (isolated, nohzFull []uint32, err error) {
	cpuRoot := filepath.Join(sysfsRoot, "cpu")
	isolated, ierr := readCPUList(filepath.Join(cpuRoot, "isolated"))
	nohzFull, nerr := readCPUList(filepath.Join(cpuRoot, "nohz_full"))
	return isolated, nohzFull, errors.Join(ierr, nerr)
}

// coreClasses reports each logical CPU's core class, and whether the node told
// it at all.
//
// Intel hybrid parts list their performance and efficiency cores under the
// kernel's cpu_core and cpu_atom PMUs. Elsewhere, ARM big.LITTLE among them,
// each CPU's cpu_capacity ranks it: the highest capacity is a performance core,
// anything lower an efficiency core, and one capacity for every CPU is a
// homogeneous part. A homogeneous x86 part has a single core PMU, the kernel's
// "cpu" device, and no cpu_capacity. When none of these is there the class cannot be told, and the
// map is empty: every CPU is then reported as unspecified, never guessed.
func coreClasses(cpus []uint32) map[uint32]info.CoreClass {
	classes := map[uint32]info.CoreClass{}
	devices := filepath.Dir(sysfsRoot)
	pCores, _ := readCPUList(filepath.Join(devices, "cpu_core", "cpus"))
	eCores, _ := readCPUList(filepath.Join(devices, "cpu_atom", "cpus"))
	if len(pCores) > 0 || len(eCores) > 0 {
		for _, cpu := range pCores {
			classes[cpu] = info.CoreClass_CORE_CLASS_PERFORMANCE
		}
		for _, cpu := range eCores {
			classes[cpu] = info.CoreClass_CORE_CLASS_EFFICIENCY
		}
		return classes
	}
	capacities := map[uint32]uint64{}
	var highest uint64
	for _, cpu := range cpus {
		capacity, ok := readUintFile(filepath.Join(sysfsRoot, "cpu",
			"cpu"+strconv.FormatUint(uint64(cpu), 10), "cpu_capacity"))
		if !ok {
			capacities = nil
			break
		}
		capacities[cpu] = capacity
		if capacity > highest {
			highest = capacity
		}
	}
	if len(capacities) > 0 {
		uniform := true
		for _, capacity := range capacities {
			if capacity != highest {
				uniform = false
			}
		}
		for cpu, capacity := range capacities {
			switch {
			case uniform:
				classes[cpu] = info.CoreClass_CORE_CLASS_UNIFORM
			case capacity == highest:
				classes[cpu] = info.CoreClass_CORE_CLASS_PERFORMANCE
			default:
				classes[cpu] = info.CoreClass_CORE_CLASS_EFFICIENCY
			}
		}
		return classes
	}
	if fi, err := os.Stat(filepath.Join(devices, "cpu")); err == nil && fi.IsDir() {
		for _, cpu := range cpus {
			classes[cpu] = info.CoreClass_CORE_CLASS_UNIFORM
		}
	}
	return classes
}

// readTextFile reads a one-line sysfs attribute, yielding "" when absent.
func readTextFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readUintFile(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// readCacheSize parses a sysfs cache size such as "32K" or "8192K" into bytes.
func readCacheSize(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	text := strings.TrimSpace(string(data))
	multiplier := uint64(1)
	switch {
	case strings.HasSuffix(text, "K"):
		multiplier, text = 1024, strings.TrimSuffix(text, "K")
	case strings.HasSuffix(text, "M"):
		multiplier, text = 1024*1024, strings.TrimSuffix(text, "M")
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value * multiplier, true
}

// readCPUList reads a kernel CPU-list file; a missing file is an empty list.
func readCPUList(path string) ([]uint32, error) {
	cpus, err := cputopology.ReadCPUListFile(path)
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, cpu := range cpus {
		out = append(out, uint32(cpu))
	}
	return out, nil
}
