// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// topoallocator.go implements a topology-aware CPU allocator that extends
// the existing CPUAllocator with NUMA/L3-cache domain awareness for RT
// workloads. RT workloads require all pinned CPUs to come from the same
// L3 CAT domain for cache isolation via Intel RDT.
//
// For non-RT workloads (RTIntent=false), allocation delegates to the
// existing simple CPUAllocator for full backward compatibility.

package cpuallocator

import (
	"fmt"
	"sort"
	"sync"

	uuid "github.com/satori/go.uuid"
)

// AllocationStatus indicates the result of a topology-aware allocation attempt.
type AllocationStatus int

const (
	// AllocSuccess means the requested CPUs were successfully allocated
	// from a single L3 domain.
	AllocSuccess AllocationStatus = iota
	// AllocNeedsRebalance means there are enough total free cores across
	// all L3 domains, but no single domain has enough. A workload reshuffle
	// or reboot may help consolidate free cores.
	AllocNeedsRebalance
	// AllocInsufficient means there are not enough free cores in the
	// entire system to satisfy the request.
	AllocInsufficient
)

// String returns a human-readable name for the allocation status.
func (s AllocationStatus) String() string {
	switch s {
	case AllocSuccess:
		return "Success"
	case AllocNeedsRebalance:
		return "NeedsRebalance"
	case AllocInsufficient:
		return "Insufficient"
	default:
		return fmt.Sprintf("Unknown(%d)", int(s))
	}
}

// AllocationResult contains the result of a topology-aware allocation attempt.
type AllocationResult struct {
	// Status indicates whether the allocation succeeded, needs rebalance,
	// or is insufficient.
	Status AllocationStatus
	// Cores is the list of allocated CPU IDs (only valid if Status == AllocSuccess)
	Cores []uint32
	// L3CATID is the L3 CAT domain ID the cores belong to
	// (only valid if Status == AllocSuccess)
	L3CATID uint
	// NUMANode is the NUMA node the cores belong to
	// (only valid if Status == AllocSuccess)
	NUMANode uint
	// Message provides human-readable detail about the allocation result
	Message string
}

// TopoAllocation tracks what was allocated for a specific domain (container).
type TopoAllocation struct {
	// UUID of the domain this allocation belongs to
	UUID uuid.UUID
	// Cores allocated to this domain
	Cores []uint32
	// L3CATID of the L3 domain the cores belong to
	L3CATID uint
	// NUMANode of the NUMA node the cores belong to
	NUMANode uint
	// RTIntent indicates this was an RT-aware allocation
	RTIntent bool
}

// TopoAwareCPUAllocator extends CPUAllocator with NUMA/cache topology
// awareness. For RT workloads (RTIntent=true), it ensures all allocated
// cores come from the same L3 CAT domain. For non-RT workloads, it
// delegates to the inner simple allocator.
type TopoAwareCPUAllocator struct {
	mu           sync.RWMutex
	inner        *CPUAllocator // existing allocator for non-RT workloads
	topology     *TopologyInfo // discovered at init time
	allocsByUUID map[uuid.UUID]*TopoAllocation
}

// InitTopoAware creates a new topology-aware CPU allocator using the
// given topology information and number of CPUs reserved for EVE services.
// The inner CPUAllocator is created for backward-compatible non-RT allocation.
func InitTopoAware(topology *TopologyInfo, numReservedForEVE uint32) (*TopoAwareCPUAllocator, error) {
	if topology == nil {
		return nil, fmt.Errorf("topology cannot be nil")
	}
	if topology.NumCores == 0 {
		return nil, fmt.Errorf("invalid topology: NumCores=%d", topology.NumCores)
	}

	inner, err := Init(topology.NumCores, numReservedForEVE)
	if err != nil {
		return nil, fmt.Errorf("failed to init inner allocator: %w", err)
	}

	return &TopoAwareCPUAllocator{
		inner:        inner,
		topology:     topology,
		allocsByUUID: make(map[uuid.UUID]*TopoAllocation),
	}, nil
}

// GetTopology returns the topology information used by this allocator.
func (a *TopoAwareCPUAllocator) GetTopology() *TopologyInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.topology
}

// Allocate allocates CPUs for a non-RT workload using the simple inner
// allocator. This is the backward-compatible path.
func (a *TopoAwareCPUAllocator) Allocate(id uuid.UUID, numCPUs int) ([]uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cpus, err := a.inner.Allocate(id, numCPUs)
	if err != nil {
		return nil, err
	}

	// Track the allocation but without topology info
	a.allocsByUUID[id] = &TopoAllocation{
		UUID:     id,
		Cores:    cpus,
		RTIntent: false,
	}

	return cpus, nil
}

// AllocateRT allocates CPUs for an RT workload, ensuring all cores come
// from the same L3 CAT domain. Returns an AllocationResult that may
// indicate success, need for rebalance, or insufficient resources.
func (a *TopoAwareCPUAllocator) AllocateRT(id uuid.UUID, numCPUs int) AllocationResult {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.allocsByUUID[id]; ok {
		return AllocationResult{
			Status:  AllocInsufficient,
			Message: fmt.Sprintf("multiple allocations for %s", id),
		}
	}

	if numCPUs <= 0 {
		return AllocationResult{
			Status:  AllocInsufficient,
			Message: "numCPUs must be > 0",
		}
	}

	// Build free-core map per L3 domain
	type domainFree struct {
		l3catID  uint
		numaNode uint
		cores    []uint32
	}

	var domains []domainFree
	totalFree := 0

	hasIsolatedCPUs := len(a.topology.IsolatedCPUs) > 0

	for _, l3 := range a.topology.L3Domains {
		var freeCores []uint32
		for _, core := range l3.Cores {
			// Skip cores reserved for EVE
			if core < a.inner.numReservedForEVE {
				continue
			}
			// RT containers must only run on isolated cores.
			// If the kernel was booted with isolcpus=, skip any
			// core that is NOT in that set — otherwise the
			// container lands on housekeeping cores that still
			// receive timer ticks, IRQs and RCU callbacks.
			if hasIsolatedCPUs && !a.topology.IsIsolated(core) {
				continue
			}
			// Skip cores already allocated to any UUID
			if a.inner.usedByAnyUUID(core) {
				continue
			}
			freeCores = append(freeCores, core)
		}

		// Find the NUMA node for this L3 domain
		var numaID uint
		if len(l3.Cores) > 0 {
			numaNode := a.topology.FindNUMANodeForCore(l3.Cores[0])
			if numaNode != nil {
				numaID = numaNode.ID
			}
		}

		if len(freeCores) > 0 {
			domains = append(domains, domainFree{
				l3catID:  l3.L3CATID,
				numaNode: numaID,
				cores:    freeCores,
			})
			totalFree += len(freeCores)
		}
	}

	// Sort domains by most free cores first, then by lowest ID for stability
	sort.Slice(domains, func(i, j int) bool {
		if len(domains[i].cores) != len(domains[j].cores) {
			return len(domains[i].cores) > len(domains[j].cores)
		}
		return domains[i].l3catID < domains[j].l3catID
	})

	// Try to find a single L3 domain with enough free cores
	for _, d := range domains {
		if len(d.cores) >= numCPUs {
			// Pick the first numCPUs cores from this domain
			selected := make([]uint32, numCPUs)
			copy(selected, d.cores[:numCPUs])

			// Record in the inner allocator
			a.inner.Lock()
			a.inner.CPUsUsedByUUIDs[id] = cpusList{cpus: selected}
			a.inner.Unlock()

			// Track topo allocation
			a.allocsByUUID[id] = &TopoAllocation{
				UUID:     id,
				Cores:    selected,
				L3CATID:  d.l3catID,
				NUMANode: d.numaNode,
				RTIntent: true,
			}

			return AllocationResult{
				Status:   AllocSuccess,
				Cores:    selected,
				L3CATID:  d.l3catID,
				NUMANode: d.numaNode,
				Message: fmt.Sprintf("allocated %d cores from L3 domain %d (NUMA %d): %v",
					numCPUs, d.l3catID, d.numaNode, selected),
			}
		}
	}

	// No single L3 domain has enough
	if totalFree >= numCPUs {
		bestCount := 0
		for _, d := range domains {
			if len(d.cores) > bestCount {
				bestCount = len(d.cores)
			}
		}
		return AllocationResult{
			Status: AllocNeedsRebalance,
			Message: fmt.Sprintf(
				"need %d cores in one L3 domain but best has %d; total free=%d across %d domains; workload reshuffle or reboot may help",
				numCPUs, bestCount, totalFree, len(domains)),
		}
	}

	return AllocationResult{
		Status: AllocInsufficient,
		Message: fmt.Sprintf(
			"not enough free cores: need %d, total free=%d",
			numCPUs, totalFree),
	}
}

// Free releases CPUs previously allocated for the given UUID.
// Works for both RT and non-RT allocations.
func (a *TopoAwareCPUAllocator) Free(id uuid.UUID) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.allocsByUUID, id)
	return a.inner.Free(id)
}

// GetAllFree returns all free CPUs (except reserved ones).
// Used for non-pinned workloads that share the free pool.
func (a *TopoAwareCPUAllocator) GetAllFree() []uint32 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.inner.GetAllFree()
}

// GetAllocation returns the topology allocation for a given UUID,
// or nil if not found.
func (a *TopoAwareCPUAllocator) GetAllocation(id uuid.UUID) *TopoAllocation {
	a.mu.RLock()
	defer a.mu.RUnlock()
	alloc, ok := a.allocsByUUID[id]
	if !ok {
		return nil
	}
	// Return a copy to prevent mutation
	copy := *alloc
	copy.Cores = make([]uint32, len(alloc.Cores))
	for i, c := range alloc.Cores {
		copy.Cores[i] = c
	}
	return &copy
}

// GetAvailabilityString returns a human-readable string showing free CPUs
// per L3 domain. Useful for debugging and logging.
func (a *TopoAwareCPUAllocator) GetAvailabilityString() string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var parts []string
	for _, l3 := range a.topology.L3Domains {
		free := 0
		for _, core := range l3.Cores {
			if core < a.inner.numReservedForEVE {
				continue
			}
			if !a.inner.usedByAnyUUID(core) {
				free++
			}
		}
		parts = append(parts, fmt.Sprintf("L3[%d]=%d/%d free",
			l3.L3CATID, free, len(l3.Cores)))
	}
	return fmt.Sprintf("CPU availability: %s", joinStrings(parts, ", "))
}

// GetInner returns the underlying simple CPUAllocator.
// This is used by non-RT paths that need direct access.
func (a *TopoAwareCPUAllocator) GetInner() *CPUAllocator {
	return a.inner
}

// joinStrings joins a slice of strings with a separator.
func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
