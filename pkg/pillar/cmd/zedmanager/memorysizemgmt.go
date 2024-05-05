// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
)

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
	memoryReservedForEve := uint64(ctxPtr.globalConfig.GlobalValueInt(types.EveMemoryLimitInBytes))
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
