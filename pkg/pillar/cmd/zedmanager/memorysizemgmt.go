// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
)

// getMemoryReservedForEveInBytes returns the amount of memory reserved for eve
// in bytes. There are two sources for this value:
// 1. Global config value `EveMemoryLimitInBytes`
// 2. Global config value `EveMemoryLimitInMiB`
// The first onve is the legacy config, as it does not support values more than 4GB.
// But we still support it for backward compatibility. If it's set to valid value,
// we use it. If it's set to 0 (which means the value set might be too high),
// we fallback to the second one.
func getMemoryReservedForEveInBytes(ctxPtr *zedmanagerContext) (uint64, error) {
	// First, check the legacy config
	memoryReservedForEveInBytes := ctxPtr.globalConfig.GlobalValueInt(types.EveMemoryLimitInBytes)
	if memoryReservedForEveInBytes != 0 {
		return uint64(memoryReservedForEveInBytes), nil
	}
	// If the legacy config is not set, or contains 0 (which means the value set might be too high),
	// fallback to the new config
	memoryReservedForEveInMiB := ctxPtr.globalConfig.GlobalValueInt(types.EveMemoryLimitInMiB)
	if memoryReservedForEveInMiB != 0 {
		return uint64(memoryReservedForEveInMiB) << 20, nil
	}
	return 0, fmt.Errorf("memoryReservedForEveInMiB is not set")

}

// getRemainingMemory returns how many bytes remain for app instance usage
// which is based on the running and about to run app instances.
// It also returns a count for the app instances which are not in those
// categories
// The amount of memory which is used but will soon be freed from halting
// app instances is returned as a third counter.
func getRemainingMemory(ctxPtr *zedmanagerContext) (uint64, uint64, uint64, error) {

	var usedMemorySize uint64    // Sum of Activated || ActivateInprogress
	var latentMemorySize uint64  // For others
	var haltingMemorySize uint64 // Subset of used which are halting
	var accountedApps []string

	pubAppInstanceStatus := ctxPtr.pubAppInstanceStatus
	itemsAppInstanceStatus := pubAppInstanceStatus.GetAll()
	for _, st := range itemsAppInstanceStatus {
		status := st.(types.AppInstanceStatus)
		mem := uint64(status.FixedResources.Memory) << 10
		mem += status.MemOverhead
		if status.Activated || status.ActivateInprogress {
			usedMemorySize += mem
			accountedApps = append(accountedApps, status.Key())
			config := lookupAppInstanceConfig(ctxPtr, status.Key(), true)
			if config == nil || !config.Activate {
				haltingMemorySize += mem
			}
		} else {
			latentMemorySize += mem
		}
	}
	memoryReservedForEve, err := getMemoryReservedForEveInBytes(ctxPtr)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("getMemoryReservedForEveInBytes failed: %v", err)
	}
	if persist.ReadPersistType() == types.PersistZFS {
		zfsArcMaxLimit, err := types.GetZFSArcMaxSizeInBytes()
		if err != nil {
			return 0, 0, 0, fmt.Errorf("failed to get data from zfs_arc_max. error: %v", err)
		}
		memoryReservedForEve += zfsArcMaxLimit
	}
	usedMemorySize += memoryReservedForEve
	deviceMemorySize, err := sysTotalMemory(ctxPtr)
	if err != nil {
		ctxPtr.checkFreedResources = true
		return 0, 0, 0, fmt.Errorf("sysTotalMemory failed: %v. Scheduling of checkRetry", err)
	}
	if usedMemorySize > deviceMemorySize {
		log.Errorf("getRemainingMemory discrepancy: accounted apps: %s; usedMemorySize: %d; deviceMemorySize: %d. Scheduling of checkRetry",
			strings.Join(accountedApps, ", "), usedMemorySize, deviceMemorySize)
		ctxPtr.checkFreedResources = true
		return 0, latentMemorySize, haltingMemorySize, nil
	} else {
		return deviceMemorySize - usedMemorySize, latentMemorySize, haltingMemorySize, nil
	}
}

func sysTotalMemory(ctx *zedmanagerContext) (uint64, error) {
	sub := ctx.subHostMemory
	m, err := sub.Get("global")
	if err != nil {
		return 0, err
	}
	if m != nil {
		memory := m.(types.HostMemory)
		return uint64(memory.TotalMemoryMB) << 20, nil
	}
	return 0, fmt.Errorf("Global host memory is empty")
}
