// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
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

	pubAppInstanceStatus := ctxPtr.pubAppInstanceStatus
	itemsAppInstanceStatus := pubAppInstanceStatus.GetAll()
	for _, st := range itemsAppInstanceStatus {
		status := st.(types.AppInstanceStatus)
		mem := uint64(status.FixedResources.Memory) << 10
		if status.Activated || status.ActivateInprogress {
			usedMemorySize += mem
			config := lookupAppInstanceConfig(ctxPtr, status.Key())
			if config == nil || !config.Activate {
				haltingMemorySize += mem
			}
		} else {
			latentMemorySize += mem
		}
	}
	memoryReservedForEve := ctxPtr.globalConfig.GlobalValueInt(types.EveMemoryLimitInBytes)
	usedMemorySize += uint64(memoryReservedForEve)
	deviceMemorySize, err := sysTotalMemory(ctxPtr)
	if err != nil {
		return 0, 0, 0, err
	}
	if usedMemorySize > deviceMemorySize {
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
