// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Network Instance/underlay network IP Address Management,
// App Number management Module

// Allocate a small integer for each application UUID.
// The number can not exceed 255 since we use the as IPv4 subnet numbers.
// Persist the numbers across reboots/activation using uuidpairtonum package
// When there are no free numbers then reuse the unused numbers.
// We try to give the application with IsZedmanager=true appnum zero.

package zedrouter

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidpairtonum"
	"github.com/satori/go.uuid"
)

// mapped on base UUID
var appNumBase map[string]*types.Bitmap

const (
	appNumOnUNetType = "appNumOnUnet"
)

// Read the existing appNums out of what we published/checkpointed.
// Also read what we have persisted before a reboot
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func appNumOnUNetInit(ctx *zedrouterContext) {

	// initialize the base
	appNumBase = make(map[string]*types.Bitmap)

	pubAppNetworkStatus := ctx.pubAppNetworkStatus
	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType

	items := pub.GetAll()
	for _, item := range items {
		appNumMap := item.(types.UUIDPairToNum)
		if appNumMap.NumType != numType {
			continue
		}
		log.Functionf("appNumOnUNetInit found %v", appNumMap)
		appNum := appNumMap.Number
		baseID := appNumMap.BaseID
		appID := appNumMap.AppID

		// If we have a config for the UUID Pair, we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		baseMap := appNumOnUNetBaseCreate(baseID)
		if baseMap.IsSet(appNum) {
			log.Errorf("Bitmap is already set for %s num %d",
				types.UUIDPairToNumKey(baseID, appID), appNum)
			continue
		}
		log.Functionf("Reserving appNum %d for %s",
			appNum, types.UUIDPairToNumKey(baseID, appID))
		baseMap.Set(appNum)
		// Clear InUse
		uuidpairtonum.NumFree(log, pub, baseID, appID)
	}
	// In case zedrouter process restarted we fill in InUse from
	// AppNetworkStatus, underlay network entries
	items = pubAppNetworkStatus.GetAll()
	for _, item := range items {
		status := item.(types.AppNetworkStatus)
		appID := status.UUIDandVersion.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		for i := range status.UnderlayNetworkList {
			ulStatus := &status.UnderlayNetworkList[i]
			baseID := ulStatus.Network
			baseMap := appNumOnUNetBaseGet(baseID)
			if baseMap == nil {
				continue
			}
			appNum, err := uuidpairtonum.NumGet(log, pub,
				baseID, appID, numType)
			if err != nil {
				continue
			}
			if !baseMap.IsSet(appNum) {
				log.Fatalf("Bitmap is not set for %s num %d",
					types.UUIDPairToNumKey(baseID, appID), appNum)
			}
			log.Functionf("Marking InUse for appNum %d",
				appNum)
			// Set InUse
			uuidpairtonum.NumAllocate(log, pub, baseID,
				appID, appNum, false, numType)
		}
	}
}

// If an entry is not inUse and and its CreateTime were
// before the agent started, then we free it up.
func appNumMapOnUNetGC(ctx *zedrouterContext) {

	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType

	log.Functionf("appNumOnUNetMapGC")
	freedCount := 0
	items := pub.GetAll()
	for _, item := range items {
		appNumMap := item.(types.UUIDPairToNum)
		if appNumMap.NumType != numType {
			continue
		}
		if appNumMap.InUse {
			continue
		}
		if appNumMap.CreateTime.After(ctx.agentStartTime) {
			continue
		}
		log.Functionf("appNumMapOnUNetGC: freeing %+v", appNumMap)
		appNumOnUNetFree(ctx, appNumMap.BaseID, appNumMap.AppID)
		freedCount++
	}
	log.Functionf("appNumMapOnUNetGC freed %d", freedCount)
}

func appNumOnUNetAllocate(ctx *zedrouterContext, baseID uuid.UUID,
	appID uuid.UUID, isStatic bool, isZedmanager bool) (int, error) {

	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType
	baseMap := appNumOnUNetBaseCreate(baseID)

	// Do we already have a number?
	appNum, err := uuidpairtonum.NumGet(log, pub, baseID, appID,
		numType)
	if err == nil {
		log.Functionf("Found allocated appNum %d for %s", appNum,
			types.UUIDPairToNumKey(baseID, appID))
		if !baseMap.IsSet(appNum) {
			log.Fatalf("Bitmap value(%d) is not set", appNum)
		}
		// Set InUse and update time
		uuidpairtonum.NumAllocate(log, pub, baseID, appID, appNum,
			false, numType)
		return appNum, nil
	}

	// Find a free number in bitmap; look for zero if isZedmanager
	if isZedmanager && !baseMap.IsSet(0) {
		appNum = 0
		log.Functionf("Allocating appNum %d for %s isZedmanager",
			appNum, types.UUIDPairToNumKey(baseID, appID))
	} else {
		// XXX could look for non-0xFF bytes first for efficiency
		appNum = -1
		// for static we pick the topmost numbers so avoid consuming
		// dynamic IP address from a smallish DHCP range.
		if isStatic {
			for i := types.BitMapMax; i >= 0; i-- {
				if !baseMap.IsSet(i) {
					appNum = i
					log.Functionf("Allocating appNum %d for %s",
						appNum, types.UUIDPairToNumKey(baseID, appID))
					break
				}
			}
		} else {
			for i := 0; i <= types.BitMapMax; i++ {
				if !baseMap.IsSet(i) {
					appNum = i
					log.Functionf("Allocating appNum %d for %s",
						appNum, types.UUIDPairToNumKey(baseID, appID))
					break
				}
			}
		}
		if appNum == -1 {
			log.Functionf("Failed to find free appNum for %s. Reusing!",
				types.UUIDPairToNumKey(baseID, appID))
			oldAppID, oldAppNum, err :=
				uuidpairtonum.NumGetOldestUnused(log, pub,
					baseID, numType)
			if err != nil {
				return appNum, fmt.Errorf("no free appNum")
			}
			log.Functionf("Reuse found appNum %d for %s. Reusing!",
				oldAppNum, types.UUIDPairToNumKey(baseID, oldAppID))
			uuidpairtonum.NumDelete(log, pub, baseID, oldAppID)
			baseMap.Clear(oldAppNum)
			appNum = oldAppNum
		}
	}
	if baseMap.IsSet(appNum) {
		log.Fatalf("Bitmap is already set for %d", appNum)
	}
	baseMap.Set(appNum)
	uuidpairtonum.NumAllocate(log, pub, baseID, appID, appNum, true,
		numType)
	return appNum, nil
}

func appNumOnUNetFree(ctx *zedrouterContext, baseID uuid.UUID,
	appID uuid.UUID) {

	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType
	appNum, err := uuidpairtonum.NumGet(log, pub, baseID, appID, numType)
	if err != nil {
		log.Fatalf("num not found for %s",
			types.UUIDPairToNumKey(baseID, appID))
	}
	baseMap := appNumOnUNetBaseGet(baseID)
	if baseMap == nil {
		uuidpairtonum.NumDelete(log, pub, baseID, appID)
		return
	}
	// Check that number exists in the allocated numbers
	if !baseMap.IsSet(appNum) {
		log.Fatalf("Bitmap is not set for %d", appNum)
	}
	baseMap.Clear(appNum)
	uuidpairtonum.NumDelete(log, pub, baseID, appID)
}

func appNumOnUNetGet(ctx *zedrouterContext, baseID uuid.UUID,
	appID uuid.UUID) (int, error) {
	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType
	return uuidpairtonum.NumGet(log, pub, baseID, appID, numType)
}

// returns base bitMap for a given UUID
func appNumOnUNetBaseGet(baseID uuid.UUID) *types.Bitmap {
	if baseMap, exist := appNumBase[baseID.String()]; exist {
		return baseMap
	}
	return nil
}

// Create application number Base for a given UUID
func appNumOnUNetBaseCreate(baseID uuid.UUID) *types.Bitmap {
	if appNumOnUNetBaseGet(baseID) == nil {
		log.Functionf("appNumOnUNetBaseCreate (%s)", baseID.String())
		appNumBase[baseID.String()] = new(types.Bitmap)
	}
	return appNumOnUNetBaseGet(baseID)
}

// Delete the application number Base for a given UUID
func appNumOnUNetBaseDelete(ctx *zedrouterContext, baseID uuid.UUID) {
	appNumMap := appNumOnUNetBaseGet(baseID)
	if appNumMap == nil {
		log.Fatalf("appNumOnUNetBaseDelete: non-existent")
	}
	// check whether there are still some apps on
	// this network
	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType
	items := pub.GetAll()
	for _, item := range items {
		appNumMap := item.(types.UUIDPairToNum)
		if appNumMap.NumType != numType {
			continue
		}
		if appNumMap.BaseID == baseID {
			log.Fatalf("appNumOnUNetBaseDelete(%s): remaining: %v",
				baseID, appNumMap)
		}
	}
	log.Functionf("appNumOnUNetBaseDelete (%s)", baseID.String())
	delete(appNumBase, baseID.String())
}

// appNumOnUNetRefCount returns the number of (remaining) references to the network
func appNumOnUNetRefCount(ctx *zedrouterContext, networkID uuid.UUID) int {
	appNumMap := appNumOnUNetBaseGet(networkID)
	if appNumMap == nil {
		log.Fatalf("appNumOnUNetRefCount: non map")
	}
	pub := ctx.pubUUIDPairToNum
	numType := appNumOnUNetType
	items := pub.GetAll()
	count := 0
	for _, item := range items {
		appNumMap := item.(types.UUIDPairToNum)
		if appNumMap.NumType != numType {
			continue
		}
		if appNumMap.BaseID == networkID {
			log.Functionf("appNumOnUNetRefCount(%s): found: %v",
				networkID, appNumMap)
			count++
		}
	}
	log.Functionf("appNumOnUNetRefCount(%s) found %d", networkID, count)
	return count
}
