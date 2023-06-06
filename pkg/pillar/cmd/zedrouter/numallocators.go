// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Initialize persisted number allocators.
func (z *zedrouter) initNumberAllocators() {
	// Pubsub topic shared for both application and bridge numbers.
	appAndBridgePublisher, err := objtonum.NewObjNumPublisher(
		z.log, z.pubSub, agentName, true, &types.UuidToNum{})
	if err != nil {
		z.log.Fatal(err)
	}

	// Initialize allocator for application numbers.
	appNumMap := objtonum.NewPublishedMap(
		z.log, appAndBridgePublisher, "appNum", objtonum.AllKeys)
	withZeroVal := false
	numAllocator := objtonum.NewByteAllocator(withZeroVal)
	z.appNumAllocator, err = objtonum.NewAllocator(z.log, numAllocator, appNumMap)
	if err != nil {
		z.log.Fatal(err)
	}

	// Mark numbers allocated for application without config as reserved-only.
	keepReserved := true
	z.appNumAllocator.FreeMultiple(objtonum.AllKeys, keepReserved)
	pubAppNetworkStatus := z.pubAppNetworkStatus
	for _, item := range pubAppNetworkStatus.GetAll() {
		status := item.(types.AppNetworkStatus)
		appNum := status.AppNum
		appNumKey := types.UuidToNumKey{UUID: status.UUIDandVersion.UUID}
		// Remove reserved-only flag.
		_, err = z.appNumAllocator.GetOrAllocate(
			appNumKey, objtonum.RequireNumber{Number: appNum})
		if err != nil {
			z.log.Errorf(
				"failed to un-reserve number %d for key %s: %v",
				appNum, appNumKey.Key(), err)
			// Continue despite the error, this is best-effort.
		}
	}

	// Initialize allocator for bridge numbers.
	brNumMap := objtonum.NewPublishedMap(
		z.log, appAndBridgePublisher, "bridgeNum", objtonum.AllKeys)
	withZeroVal = false
	numAllocator = objtonum.NewByteAllocator(withZeroVal)
	z.bridgeNumAllocator, err = objtonum.NewAllocator(z.log, numAllocator, brNumMap)
	if err != nil {
		z.log.Fatal(err)
	}

	// Mark numbers allocated for bridges without config as reserved-only.
	z.bridgeNumAllocator.FreeMultiple(objtonum.AllKeys, keepReserved)
	for _, item := range z.pubNetworkInstanceStatus.GetAll() {
		status := item.(types.NetworkInstanceStatus)
		bridgeNum := status.BridgeNum
		bridgeNumKey := types.UuidToNumKey{UUID: status.UUID}
		// Remove reserved-only flag.
		_, err = z.bridgeNumAllocator.GetOrAllocate(
			bridgeNumKey, objtonum.RequireNumber{Number: bridgeNum})
		if err != nil {
			z.log.Errorf(
				"failed to un-reserve number %d for key %s: %v",
				bridgeNum, bridgeNumKey.Key(), err)
			// Continue despite the error, this is best-effort.
		}
	}

	// Initialize number allocators for application interfaces.
	// Every configured network instance has its own allocator.
	z.appIntfNumPublisher, err = objtonum.NewObjNumPublisher(
		z.log, z.pubSub, agentName, true, &types.AppInterfaceToNum{})
	if err != nil {
		z.log.Fatal(err)
	}
	z.appIntfNumAllocator = make(map[string]*objtonum.Allocator)
	for _, num := range z.appIntfNumPublisher.GetAll() {
		intfNum := num.(*types.AppInterfaceToNum)
		// Create allocator for this network instance if it does not exist yet.
		z.getOrAddAppIntfAllocator(intfNum.NetInstID)
	}

	// Mark numbers allocated for app-interfaces without config as reserved-only.
	// First cycle turns all existing allocations into reservations, the second removes
	// reserved-only flags for app-interfaces with config.
	for _, allocator := range z.appIntfNumAllocator {
		allocator.FreeMultiple(objtonum.AllKeys, keepReserved)
	}
	for _, item := range pubAppNetworkStatus.GetAll() {
		status := item.(types.AppNetworkStatus)
		var unets []types.UnderlayNetworkConfig
		for _, unet := range status.UnderlayNetworkList {
			unets = append(unets, unet.UnderlayNetworkConfig)
		}
		err = z.allocateAppIntfNums(status.UUIDandVersion.UUID, unets)
		if err != nil {
			z.log.Errorf(
				"failed to sync AppInterfaceToNum with AppNetworkStatus for app %s-%s: %v",
				status.DisplayName, status.UUIDandVersion.UUID, err)
			// Continue despite the error, this is best-effort.
		}
	}
}

// Either get existing or create a new allocator for app-interfaces connected
// to a given network instance.
func (z *zedrouter) getOrAddAppIntfAllocator(netInstID uuid.UUID) *objtonum.Allocator {
	netInstKey := netInstID.String()
	allocator, hasAllocator := z.appIntfNumAllocator[netInstKey]
	if !hasAllocator {
		keySelector := func(key objtonum.ObjKey) bool {
			return key.(types.AppInterfaceKey).NetInstID == netInstID
		}
		appNumMap := objtonum.NewPublishedMap(
			z.log, z.appIntfNumPublisher, "appNumOnUnet", keySelector)
		withZeroVal := true
		numAllocator := objtonum.NewByteAllocator(withZeroVal)
		var err error
		allocator, err = objtonum.NewAllocator(z.log, numAllocator, appNumMap)
		if err != nil {
			z.log.Fatal(err)
		}
		z.appIntfNumAllocator[netInstKey] = allocator
	}
	return allocator
}

// Delete allocator used for app-interfaces connected to a given network instance.
func (z *zedrouter) delAppIntfAllocator(netInstID uuid.UUID) error {
	netInstKey := netInstID.String()
	allocator, hasAllocator := z.appIntfNumAllocator[netInstKey]
	if !hasAllocator {
		// Nothing to do.
		return nil
	}
	allocCount, _ := allocator.AllocatedCount()
	if allocCount > 0 {
		return fmt.Errorf(
			"cannot delete app-interface allocator for network instance %s: "+
				"the set of allocated numbers is not empty (%d)", netInstID, allocCount)
	}
	delete(z.appIntfNumAllocator, netInstKey)
	return nil
}

// Allocate numbers for all interfaces of a given app.
func (z *zedrouter) allocateAppIntfNums(appID uuid.UUID,
	unets []types.UnderlayNetworkConfig) error {
	for _, ulConfig := range unets {
		netInstID := ulConfig.Network
		ifIdx := ulConfig.IfIdx
		withStaticIP := ulConfig.AppIPAddr != nil
		err := z.allocateAppIntfNum(netInstID, appID, ifIdx, withStaticIP)
		if err != nil {
			return err
		}
	}
	return nil
}

// Allocate number for a single interface of a given app.
func (z *zedrouter) allocateAppIntfNum(netInstID uuid.UUID, appID uuid.UUID,
	ifIdx uint32, withStaticIP bool) error {
	appIntfKey := types.AppInterfaceKey{
		NetInstID: netInstID,
		AppID:     appID,
		IfIdx:     ifIdx,
	}
	allocStrategy := objtonum.LowestFree
	if withStaticIP {
		// For static IP we pick the topmost numbers so avoid consuming
		// dynamic IP address from a smallish DHCP range.
		allocStrategy = objtonum.HighestFree
	}
	allocator := z.getOrAddAppIntfAllocator(netInstID)
	_, err := allocator.GetOrAllocate(appIntfKey, allocStrategy)
	if err != nil {
		return fmt.Errorf("failed to allocate num for app interface %s: %v",
			appIntfKey.Key(), err)
	}
	return nil
}

// Get number which was already allocated to a given app-interface.
func (z *zedrouter) getAppIntfNum(netInstID uuid.UUID, appID uuid.UUID,
	ifIdx uint32) (int, error) {
	appIntfKey := types.AppInterfaceKey{
		NetInstID: netInstID,
		AppID:     appID,
		IfIdx:     ifIdx,
	}
	allocator := z.getOrAddAppIntfAllocator(netInstID)
	// The number has been already allocated and will be just returned.
	return allocator.GetOrAllocate(appIntfKey)
}

// Free numbers allocated for interfaces of a given app.
func (z *zedrouter) freeAppIntfNums(status *types.AppNetworkStatus) {
	appID := status.UUIDandVersion.UUID
	for _, ulStatus := range status.UnderlayNetworkList {
		netInstID := ulStatus.Network
		ifIdx := ulStatus.IfIdx
		err := z.freeAppIntfNum(netInstID, appID, ifIdx)
		if err != nil {
			// Just log error and continue. Try to free as many numbers as possible.
			z.log.Error(err)
		}
	}
}

// Free number allocated for a single interface of a given app.
func (z *zedrouter) freeAppIntfNum(netInstID uuid.UUID, appID uuid.UUID,
	ifIdx uint32) error {
	appIntfKey := types.AppInterfaceKey{
		NetInstID: netInstID,
		AppID:     appID,
		IfIdx:     ifIdx,
	}
	allocator := z.getOrAddAppIntfAllocator(netInstID)
	err := allocator.Free(appIntfKey, false)
	if err != nil {
		err = fmt.Errorf("failed to free num allocated for app interface %s: %v",
			appIntfKey.Key(), err)
		return err
	}
	return nil
}

// Remove reserved-only numbers that originated from before the last agent restart.
func (z *zedrouter) gcNumAllocators() {
	err := z.bridgeNumAllocator.GC(z.agentStartTime)
	if err != nil {
		z.log.Warnf("bridgeNumAllocator GC failed: %v", err)
	}
	err = z.appNumAllocator.GC(z.agentStartTime)
	if err != nil {
		z.log.Warnf("appNumAllocator GC failed: %v", err)
	}
	for netInst, appIntfAllocator := range z.appIntfNumAllocator {
		err = appIntfAllocator.GC(z.agentStartTime)
		if err != nil {
			z.log.Warnf("appIntfAllocator (%s) GC failed: %v", netInst, err)
		}
	}
}
