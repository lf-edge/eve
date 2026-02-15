// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// topology.go defines types and functions for discovering CPU/cache/NUMA topology
// using pqos (Intel RDT) capabilities. This information is used by the
// topology-aware CPU allocator to ensure RT workloads get cores from the same
// L3 cache domain for optimal cache locality and RDT isolation.

package cpuallocator

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/intel/intel-cmt-cat/lib/go/pqos"
)

// TopologyInfo represents the system's CPU/cache/NUMA topology discovered
// from pqos hardware interrogation.
type TopologyInfo struct {
	// NumCores is the total number of logical cores in the system
	NumCores uint32
	// L3Domains groups cores by shared L3 cache (L3 CAT domain)
	L3Domains []L3Domain
	// NUMANodes groups cores by NUMA memory domain
	NUMANodes []NUMANode
	// RDTCapable is true if L3 CAT hardware is available
	RDTCapable bool
	// IsolatedCPUs is the set of CPUs isolated via isolcpus= kernel parameter
	IsolatedCPUs []uint32
}

// L3Domain groups cores that share an L3 cache and a set of CLOS definitions.
// All cores in the same L3 CAT domain share the same set of CLOS IDs.
// The topology-aware allocator must assign all pinned CPUs for an RT domain
// from the same L3 CAT domain.
type L3Domain struct {
	// L3CATID is the L3 CAT classes ID that groups these cores
	L3CATID uint
	// MBAID is the MBA ID for this domain (usually 1:1 with L3CATID)
	MBAID uint
	// Cores is the list of logical core IDs sharing this L3 cache
	Cores []uint32
	// CacheSize is the total L3 cache size for this domain in bytes
	CacheSize uint64
	// NumWays is the number of cache ways in this L3 domain
	NumWays uint
	// WaySize is the size of each cache way in bytes
	WaySize uint64
}

// NUMANode groups cores in the same memory domain.
type NUMANode struct {
	// ID is the NUMA node identifier
	ID uint
	// Cores is the list of logical core IDs in this NUMA node
	Cores []uint32
	// L3Domains is the list of L3CATID values present in this NUMA node
	L3Domains []uint
}

// BuildTopologyFromPQoS constructs a TopologyInfo from pqos capability data.
// This is the primary way to discover topology on systems with RDT support.
func BuildTopologyFromPQoS(cap *pqos.Capability) (*TopologyInfo, error) {
	cpuInfo, err := cap.GetCPUInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get CPU info: %w", err)
	}

	topo := &TopologyInfo{
		NumCores:   uint32(cpuInfo.NumCores),
		RDTCapable: cap.HasL3CA(),
	}

	// Read isolated CPUs from kernel cmdline
	topo.IsolatedCPUs = readIsolatedCPUs()

	// Group cores by L3CATID
	l3Groups := map[uint][]uint32{}
	l3MBAID := map[uint]uint{}
	for _, core := range cpuInfo.Cores {
		l3Groups[core.L3CATID] = append(l3Groups[core.L3CATID], uint32(core.LCore))
		l3MBAID[core.L3CATID] = core.MBAID
	}

	// Get L3 cache capability info if available
	var l3NumWays uint
	var l3WaySize uint64
	if cap.HasL3CA() {
		l3Cap, err := cap.GetL3CA()
		if err == nil {
			l3NumWays = l3Cap.NumWays
			l3WaySize = uint64(l3Cap.WaySize)
		}
	}
	// Fall back to cpuInfo L3 data if capability query didn't work
	if l3NumWays == 0 && cpuInfo.L3.Detected {
		l3NumWays = cpuInfo.L3.NumWays
		l3WaySize = uint64(cpuInfo.L3.WaySize)
	}

	// Build L3Domain structs
	var l3Domains []L3Domain
	for catID, cores := range l3Groups {
		sortUint32s(cores)
		l3Domains = append(l3Domains, L3Domain{
			L3CATID:   catID,
			MBAID:     l3MBAID[catID],
			Cores:     cores,
			NumWays:   l3NumWays,
			WaySize:   l3WaySize,
			CacheSize: uint64(l3NumWays) * l3WaySize,
		})
	}
	// Sort by L3CATID for deterministic ordering
	sort.Slice(l3Domains, func(i, j int) bool {
		return l3Domains[i].L3CATID < l3Domains[j].L3CATID
	})
	topo.L3Domains = l3Domains

	// Group cores by NUMA node
	numaGroups := map[uint][]uint32{}
	numaL3 := map[uint]map[uint]bool{}
	for _, core := range cpuInfo.Cores {
		numaGroups[core.NUMA] = append(numaGroups[core.NUMA], uint32(core.LCore))
		if numaL3[core.NUMA] == nil {
			numaL3[core.NUMA] = make(map[uint]bool)
		}
		numaL3[core.NUMA][core.L3CATID] = true
	}

	var numaNodes []NUMANode
	for numaID, cores := range numaGroups {
		sortUint32s(cores)
		var l3IDs []uint
		for id := range numaL3[numaID] {
			l3IDs = append(l3IDs, id)
		}
		sort.Slice(l3IDs, func(i, j int) bool { return l3IDs[i] < l3IDs[j] })
		numaNodes = append(numaNodes, NUMANode{
			ID:        numaID,
			Cores:     cores,
			L3Domains: l3IDs,
		})
	}
	// Sort by NUMA ID for deterministic ordering
	sort.Slice(numaNodes, func(i, j int) bool {
		return numaNodes[i].ID < numaNodes[j].ID
	})
	topo.NUMANodes = numaNodes

	return topo, nil
}

// BuildTopologyFallback constructs a minimal TopologyInfo without pqos,
// using only the total CPU count and the number of reserved CPUs.
// All cores are placed in a single L3 domain and single NUMA node.
// This is used when RDT hardware is not available.
func BuildTopologyFallback(totalCPUs uint32) *TopologyInfo {
	cores := make([]uint32, totalCPUs)
	for i := uint32(0); i < totalCPUs; i++ {
		cores[i] = i
	}

	return &TopologyInfo{
		NumCores:   totalCPUs,
		RDTCapable: false,
		L3Domains: []L3Domain{
			{
				L3CATID: 0,
				MBAID:   0,
				Cores:   cores,
			},
		},
		NUMANodes: []NUMANode{
			{
				ID:        0,
				Cores:     cores,
				L3Domains: []uint{0},
			},
		},
		IsolatedCPUs: readIsolatedCPUs(),
	}
}

// FindL3DomainForCore returns the L3Domain that contains the given core,
// or nil if not found.
func (t *TopologyInfo) FindL3DomainForCore(core uint32) *L3Domain {
	for i := range t.L3Domains {
		for _, c := range t.L3Domains[i].Cores {
			if c == core {
				return &t.L3Domains[i]
			}
		}
	}
	return nil
}

// FindNUMANodeForCore returns the NUMANode that contains the given core,
// or nil if not found.
func (t *TopologyInfo) FindNUMANodeForCore(core uint32) *NUMANode {
	for i := range t.NUMANodes {
		for _, c := range t.NUMANodes[i].Cores {
			if c == core {
				return &t.NUMANodes[i]
			}
		}
	}
	return nil
}

// IsIsolated returns true if the given CPU is in the isolcpus= set.
func (t *TopologyInfo) IsIsolated(cpu uint32) bool {
	for _, c := range t.IsolatedCPUs {
		if c == cpu {
			return true
		}
	}
	return false
}

// readIsolatedCPUs parses the isolcpus= parameter from /proc/cmdline
// and returns the list of isolated CPU IDs.
func readIsolatedCPUs() []uint32 {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil
	}
	return parseIsolatedCPUsFromCmdline(string(data))
}

// parseIsolatedCPUsFromCmdline extracts isolated CPU IDs from a kernel
// command line string. Exported for testing.
func parseIsolatedCPUsFromCmdline(cmdline string) []uint32 {
	scanner := bufio.NewScanner(strings.NewReader(cmdline))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		word := scanner.Text()
		if strings.HasPrefix(word, "isolcpus=") {
			cpuList := strings.TrimPrefix(word, "isolcpus=")
			// isolcpus= can have flags like "managed_irq," prefix
			// e.g., "isolcpus=managed_irq,domain,1-7"
			// The CPU list is after the last comma-separated group
			// that starts with a digit or contains a dash with digits.
			// Simple approach: parse from the value, skip known flag prefixes
			cpuList = stripIsolcpusFlags(cpuList)
			return parseCPUList(cpuList)
		}
	}
	return nil
}

// stripIsolcpusFlags removes known flag prefixes from isolcpus value.
// isolcpus= format: [flag1,flag2,]cpu_list
// Known flags: managed_irq, domain, nohz
func stripIsolcpusFlags(value string) string {
	knownFlags := map[string]bool{
		"managed_irq": true,
		"domain":      true,
		"nohz":        true,
	}

	parts := strings.Split(value, ",")
	// Find where CPU list starts (first part that looks like a number or range)
	for i, part := range parts {
		if !knownFlags[part] {
			// This should be the start of the CPU list
			return strings.Join(parts[i:], ",")
		}
	}
	return value
}

// parseCPUList parses a CPU list string like "1-3,5,7-9" into
// a sorted slice of individual CPU IDs [1,2,3,5,7,8,9].
func parseCPUList(cpuList string) []uint32 {
	if cpuList == "" {
		return nil
	}

	var result []uint32
	parts := strings.Split(cpuList, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				continue
			}
			start, err1 := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 32)
			end, err2 := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 32)
			if err1 != nil || err2 != nil || start > end {
				continue
			}
			for cpu := uint32(start); cpu <= uint32(end); cpu++ {
				result = append(result, cpu)
			}
		} else {
			cpu, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				continue
			}
			result = append(result, uint32(cpu))
		}
	}

	sortUint32s(result)
	return result
}

// sortUint32s sorts a slice of uint32 in ascending order.
func sortUint32s(s []uint32) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

// String returns a human-readable summary of the topology.
func (t *TopologyInfo) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Topology: %d cores, %d L3 domains, %d NUMA nodes, RDT=%v",
		t.NumCores, len(t.L3Domains), len(t.NUMANodes), t.RDTCapable)
	for _, d := range t.L3Domains {
		fmt.Fprintf(&sb, "\n  L3 domain %d (MBA %d): cores=%v, cache=%d bytes (%d ways x %d bytes)",
			d.L3CATID, d.MBAID, d.Cores, d.CacheSize, d.NumWays, d.WaySize)
	}
	for _, n := range t.NUMANodes {
		fmt.Fprintf(&sb, "\n  NUMA node %d: cores=%v, L3 domains=%v",
			n.ID, n.Cores, n.L3Domains)
	}
	if len(t.IsolatedCPUs) > 0 {
		fmt.Fprintf(&sb, "\n  Isolated CPUs: %v", t.IsolatedCPUs)
	}
	return sb.String()
}
