// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// getRemainingMemory returns how many bytes remain for app instance usage
func getRemainingMemory(ctxPtr *zedmanagerContext) (uint64, error) {

	var usedMemorySize uint64
	pubAppInstanceStatus := ctxPtr.pubAppInstanceStatus
	itemsAppInstanceStatus := pubAppInstanceStatus.GetAll()
	for _, iterAppInstanceStatusJSON := range itemsAppInstanceStatus {
		iterAppInstanceStatus := iterAppInstanceStatusJSON.(types.AppInstanceStatus)
		usedMemorySize += uint64(iterAppInstanceStatus.FixedResources.Memory) << 10
	}
	memoryReservedForEve := ctxPtr.globalConfig.GlobalValueInt(types.EveMemoryLimitInBytes)
	usedMemorySize += uint64(memoryReservedForEve)
	deviceMemorySize, err := sysTotalMemory(ctxPtr)
	if err != nil {
		return 0, err
	}
	return deviceMemorySize - usedMemorySize, nil
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
