// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"fmt"
	"sync"

	uuid "github.com/satori/go.uuid"
)

type cpusList struct {
	cpus []uint32
}

func (cpus *cpusList) contains(cpuToCheck uint32) bool {
	for _, cpu := range cpus.cpus {
		if cpu == cpuToCheck {
			return true
		}
	}
	return false
}

// CPUAllocator stores information about the CPUs available in the system
// and provides interface to allocate and free them, per UUID.
type CPUAllocator struct {
	sync.RWMutex                             // lock the access to the allocator
	CPUsUsedByUUIDs   map[uuid.UUID]cpusList // per UUID list of allocated CPUs
	totalCPUs         uint32                 // total amount of CPUs in the system
	numReservedForEVE uint32                 // amount of the CPUs reserved for the EVE services
}

// Init initializes a CPUAllocator instance.
// totalCPUs is the number of CPUs available is the system,
// numReserved is the number of CPUs considered to be always free, reserved for
// the EVE services and VMs with no CPU pinning enabled.
func Init(totalCPUs uint32, numReserved uint32) (*CPUAllocator, error) {
	if totalCPUs == 0 || numReserved >= totalCPUs {
		return nil, fmt.Errorf("invalid totalCPUs %d and/or numReserved %d",
			totalCPUs, numReserved)
	}
	return &CPUAllocator{
		CPUsUsedByUUIDs:   make(map[uuid.UUID]cpusList),
		totalCPUs:         totalCPUs,
		numReservedForEVE: numReserved,
	}, nil
}

// Allocate a list of CPUs for a given uuid. If the amount of available CPUs is
// less than the requested amount (numCPUs), return an error and an empty list.
// If an allocation for a given uuid was already done before, also return an error
// and an empty list.
func (cpuAllocator *CPUAllocator) Allocate(uuid uuid.UUID, numCPUs int) ([]uint32, error) {
	cpuAllocator.Lock()
	defer cpuAllocator.Unlock()
	if _, ok := cpuAllocator.CPUsUsedByUUIDs[uuid]; ok {
		// Already allocated; return error
		return []uint32{}, fmt.Errorf("multiple allocations for %s", uuid)
	}
	list, err := cpuAllocator.getFree(numCPUs)
	if err != nil {
		return list, err
	}
	cpuAllocator.CPUsUsedByUUIDs[uuid] = cpusList{cpus: list}
	return list, nil
}

// Free the CPUs previously allocated for a given uuid.
// Return an error for an attempt to free CPUs for a uuid that has no allocated CPUs.
func (cpuAllocator *CPUAllocator) Free(uuid uuid.UUID) error {
	cpuAllocator.Lock()
	defer cpuAllocator.Unlock()
	if _, ok := cpuAllocator.CPUsUsedByUUIDs[uuid]; !ok {
		// Nothing allocated; return error
		return fmt.Errorf("free but no allocation for %s", uuid)
	}
	delete(cpuAllocator.CPUsUsedByUUIDs, uuid)
	return nil
}

func (cpuAllocator *CPUAllocator) usedByAnyUUID(cpuToCheck uint32) bool {
	for _, cpus := range cpuAllocator.CPUsUsedByUUIDs {
		if cpus.contains(cpuToCheck) {
			return true
		}
	}
	return false
}

// Find the lowest numbered free CPUs, skipping the reserved ones
func (cpuAllocator *CPUAllocator) getFree(numCPUsRequested int) ([]uint32, error) {
	result := make([]uint32, 0, cpuAllocator.totalCPUs)
	found := 0
	var cpu uint32
	for cpu = cpuAllocator.numReservedForEVE; cpu < cpuAllocator.totalCPUs && found < numCPUsRequested; cpu++ {
		if !cpuAllocator.usedByAnyUUID(cpu) {
			result = append(result, cpu)
			found++
		}
	}
	if found < numCPUsRequested {
		return []uint32{}, fmt.Errorf("looking for %d CPUs only found %d",
			numCPUsRequested, found)
	}
	return result, nil
}

// GetAllFree returns all free CPUs (except the reserved ones)
func (cpuAllocator *CPUAllocator) GetAllFree() []uint32 {
	cpuAllocator.RLock()
	defer cpuAllocator.RUnlock()
	result := make([]uint32, 0, cpuAllocator.totalCPUs)
	var cpu uint32
	for cpu = 0; cpu < cpuAllocator.totalCPUs; cpu++ {
		if !cpuAllocator.usedByAnyUUID(cpu) {
			result = append(result, cpu)
		}
	}
	return result
}
