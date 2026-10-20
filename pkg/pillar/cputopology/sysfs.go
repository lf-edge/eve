// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// defaultSysfsRoot is the standard Linux sysfs location for CPU and NUMA
// node topology information.
var defaultSysfsRoot = "/sys/devices/system"

// ErrNoCPUTopology reports that sysfs exposed no usable CPU topology at all
// (an empty "online" file, or no cpuN directories), as opposed to exposing
// something that could not be read.
var ErrNoCPUTopology = errors.New("sysfs exposed no usable CPU topology")

// DiscoverTopology reads CPU topology from sysfs. The returned *Topology is
// always non-nil: on failure it degrades to a flat single-thread-per-core
// model so reporting paths keep working. A non-nil error therefore means the
// topology is degraded (Topology.Degraded set), not absent, and callers doing
// CPU placement must refuse it rather than fall back to it.
func DiscoverTopology() (*Topology, error) {
	infos, err := readSysfsCoreInfos(defaultSysfsRoot)
	if err == nil && len(infos) == 0 {
		err = ErrNoCPUTopology
	}
	if err != nil {
		return flatTopology(fallbackCPUs(filepath.Join(defaultSysfsRoot, "cpu"))), err
	}
	return BuildTopology(infos), nil
}

// fallbackCPUs is the CPU set a degraded topology is built on: the online CPUs
// when sysfs lists them, else as many as this process may run on. The process's
// count alone is not enough: pillar runs in the cpuset of the CPUs reserved for
// EVE, so it would leave every other CPU out of the model.
func fallbackCPUs(cpuRoot string) []uint {
	if cpus, err := readOnlineCPUs(cpuRoot); err == nil && len(cpus) > 0 {
		return cpus
	}
	cpus := make([]uint, max(runtime.NumCPU(), 1))
	for i := range cpus {
		cpus[i] = uint(i)
	}
	return cpus
}

// flatTopology builds a degraded topology of single-thread physical cores, one
// per given CPU, all on socket 0 / NUMA node 0, with unknown L3 ids. Used when
// sysfs discovery fails, hence Topology.Degraded - see its documentation.
func flatTopology(cpus []uint) *Topology {
	if len(cpus) == 0 {
		cpus = []uint{0}
	}
	infos := make([]CoreInfo, len(cpus))
	for i, cpu := range cpus {
		// Nothing is known about the cache hierarchy here, and saying "L3 domain
		// 0" would claim every CPU shares one cache.
		infos[i] = CoreInfo{LCore: cpu, Socket: 0, CoreID: cpu, NUMA: 0,
			L3Unknown: true}
	}
	topo := BuildTopology(infos)
	topo.Degraded = true
	return topo
}

// readSysfsCoreInfos reads per-logical-CPU topology coordinates from a
// sysfs tree rooted at root (normally /sys/devices/system; tests inject a
// temp dir with the same layout).
func readSysfsCoreInfos(root string) ([]CoreInfo, error) {
	cpuRoot := filepath.Join(root, "cpu")

	online, err := readOnlineCPUs(cpuRoot)
	if err != nil {
		return nil, err
	}

	nodeOfCPU, numaExposed, err := readNUMAMapping(root)
	if err != nil {
		return nil, err
	}

	infos := make([]CoreInfo, 0, len(online))
	lead := map[uint]uint{}
	for _, cpu := range online {
		ci := CoreInfo{LCore: cpu}

		cpuDir := filepath.Join(cpuRoot, fmt.Sprintf("cpu%d", cpu))

		if v, ok := readOptionalUint(filepath.Join(cpuDir, "topology", "physical_package_id")); ok {
			ci.Socket = v
		} else {
			ci.Socket = 0
		}

		coreID, err := readRequiredUint(filepath.Join(cpuDir, "topology", "core_id"))
		if err != nil {
			return nil, fmt.Errorf("cpu%d: missing core_id: %w", cpu, err)
		}
		ci.CoreID = coreID
		if data, err := os.ReadFile(filepath.Join(cpuDir, "topology", "thread_siblings_list")); err == nil {
			if siblings, err := ParseCPUList(string(data)); err == nil && len(siblings) > 0 {
				lead[cpu] = slices.Min(siblings)
			}
		}

		var l3Known bool
		ci.L3ID, l3Known = readL3ID(filepath.Join(cpuDir, "cache"))
		ci.L3Unknown = !l3Known

		// A CPU missing from the node listings while the kernel does expose
		// NUMA information is a hole in the model, not a hint that it lives on
		// node 0: guessing would let a single-NUMA-node placement request be
		// satisfied with cores from two sockets and reported as optimal.
		if numa, ok := nodeOfCPU[cpu]; ok {
			ci.NUMA = numa
		} else if numaExposed {
			return nil, fmt.Errorf("cpu%d: no NUMA node covers it in %s",
				cpu, filepath.Join(root, "node"))
		}

		infos = append(infos, ci)
	}

	renumberClusteredCores(infos, lead)
	return infos, nil
}

// renumberClusteredCores makes CoreID unique within its socket. The kernel's
// core_id is on x86, but on ARM64 with a device-tree cpu-map it restarts in
// every cluster (the kernel tells those cores apart by cluster_id), and cores
// of different clusters would be grouped as SMT siblings of one core. In a
// socket where one core_id covers more than one sibling set, as the kernel's
// thread_siblings_list reports them, every core is numbered by its lowest
// logical CPU instead.
func renumberClusteredCores(infos []CoreInfo, lead map[uint]uint) {
	type key struct{ socket, coreID uint }
	leads := map[key]map[uint]bool{}
	for _, ci := range infos {
		l, ok := lead[ci.LCore]
		if !ok {
			continue
		}
		k := key{ci.Socket, ci.CoreID}
		if leads[k] == nil {
			leads[k] = map[uint]bool{}
		}
		leads[k][l] = true
	}
	clash := map[uint]bool{}
	for k, l := range leads {
		if len(l) > 1 {
			clash[k.socket] = true
		}
	}
	for i := range infos {
		if l, ok := lead[infos[i].LCore]; ok && clash[infos[i].Socket] {
			infos[i].CoreID = l
		}
	}
}

// readOnlineCPUs returns the online logical CPU ids in ascending order.
func readOnlineCPUs(cpuRoot string) ([]uint, error) {
	cpus, err := readOnlineCPUsUnordered(cpuRoot)
	if err != nil {
		return nil, err
	}
	// Ascending order is an enforced postcondition, not an observation about
	// the kernel's output: SMT sibling selection picks Siblings[0] as the
	// thread to run on, so it must not depend on file or directory ordering.
	slices.Sort(cpus)
	return cpus, nil
}

// readOnlineCPUsUnordered reads <cpuRoot>/online (a Linux cpu range list,
// e.g. "0-7,16") and falls back to enumerating <cpuRoot>/cpuN directories if
// that file is missing.
func readOnlineCPUsUnordered(cpuRoot string) ([]uint, error) {
	onlinePath := filepath.Join(cpuRoot, "online")
	data, err := os.ReadFile(onlinePath)
	if err == nil {
		return ParseCPUList(string(data))
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", onlinePath, err)
	}

	entries, err := os.ReadDir(cpuRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", cpuRoot, err)
	}
	var cpus []uint
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "cpu") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(name, "cpu"), 10, 32)
		if err != nil {
			continue
		}
		cpus = append(cpus, uint(n))
	}
	return cpus, nil
}

// readNUMAMapping builds a map from logical CPU id to NUMA node id by
// reading <root>/node/node*/cpulist. exposed is false when <root>/node does
// not exist at all, i.e. the kernel publishes no NUMA information; the caller
// then treats the whole machine as node 0, which is the truth on such a
// system. A node directory that does exist but whose cpulist cannot be read
// or parsed is an error instead: quietly defaulting those CPUs to node 0
// would fabricate NUMA locality that a placement decision then trusts.
func readNUMAMapping(root string) (mapping map[uint]uint, exposed bool, err error) {
	nodeRoot := filepath.Join(root, "node")
	entries, err := os.ReadDir(nodeRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return map[uint]uint{}, false, nil
		}
		return nil, false, fmt.Errorf("reading %s: %w", nodeRoot, err)
	}

	mapping = map[uint]uint{}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "node") {
			continue
		}
		nodeID, err := strconv.ParseUint(strings.TrimPrefix(name, "node"), 10, 32)
		if err != nil {
			continue
		}
		cpulistPath := filepath.Join(nodeRoot, name, "cpulist")
		data, err := os.ReadFile(cpulistPath)
		if err != nil {
			return nil, true, fmt.Errorf("reading %s: %w", cpulistPath, err)
		}
		// An empty cpulist is legitimate: a memory-only node has no CPUs.
		cpus, err := ParseCPUList(string(data))
		if err != nil {
			return nil, true, fmt.Errorf("parsing %s: %w", cpulistPath, err)
		}
		for _, cpu := range cpus {
			mapping[cpu] = uint(nodeID)
		}
	}
	return mapping, true, nil
}

// readL3ID finds the cache index under cacheDir whose level file contains
// "3" and returns its id. ok is false when the platform exposes no such id -
// no readable cache directory, no level-3 index, or an index without an "id"
// file (common on ARM64). An unknown id must stay distinguishable from a real
// id 0, otherwise every core appears to share one L3 domain and a
// cache-splitting placement is never noticed.
func readL3ID(cacheDir string) (uint, bool) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "index") {
			continue
		}
		levelPath := filepath.Join(cacheDir, name, "level")
		level, ok := readOptionalUint(levelPath)
		if !ok || level != 3 {
			continue
		}
		return readOptionalUint(filepath.Join(cacheDir, name, "id"))
	}
	return 0, false
}

// readOptionalUint reads a single unsigned integer from path, treating
// any error (missing file, parse failure) or a negative value (e.g. "-1"
// for physical_package_id on single-socket systems) as "not present".
func readOptionalUint(path string) (uint, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return uint(n), true
}

// readRequiredUint reads a single unsigned integer from path, returning
// an error if the file is missing, unparsable, or negative.
func readRequiredUint(path string) (uint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s (%q): %w", path, s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("parsing %s: unexpected negative value %d", path, n)
	}
	return uint(n), nil
}

// ReadCPUListFile reads a kernel CPU-list file such as cpu/isolated. A missing
// file is an empty list: the kernel omits some of them when the feature they
// describe is unused.
func ReadCPUListFile(path string) ([]uint, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cpus, err := ParseCPUList(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cpus, nil
}

// ParseCPUList parses the kernel's CPU-list format, such as "0-3,7", into
// []uint{0,1,2,3,7}. Surrounding whitespace is ignored, and so is "(null)",
// which is what the kernel prints for a mask it never allocated (nohz_full on
// a kernel booted without it).
func ParseCPUList(s string) ([]uint, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "(null)" {
		return nil, nil
	}
	var result []uint
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.Index(part, "-"); idx >= 0 {
			lo, err := strconv.ParseUint(part[:idx], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing range %q: %w", part, err)
			}
			hi, err := strconv.ParseUint(part[idx+1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing range %q: %w", part, err)
			}
			for v := lo; v <= hi; v++ {
				result = append(result, uint(v))
			}
		} else {
			v, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing cpu id %q: %w", part, err)
			}
			result = append(result, uint(v))
		}
	}
	return result, nil
}
