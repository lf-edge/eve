// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Allocate a small integer for each application UUID.
// The number can not exceed 255 since we use the as IPv4 subnet numbers.
// Persist the numbers across reboots using uuidtonum package
// When there are no free numbers then reuse the unused numbers.
// We try to give the application with IsZedmanager=true appnum zero.

package zedrouter

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uuidtonum"
	"github.com/satori/go.uuid"
)

var AllocReservedAppNumBits types.Bitmap

const (
	appNumType = "appNum"
)

// Read the existing appNums out of what we published/checkpointed.
// Also read what we have persisted before a reboot
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func appNumAllocatorInit(ctx *zedrouterContext) {

	pubAppNetworkStatus := ctx.pubAppNetworkStatus
	pub := ctx.pubUuidToNum
	numType := appNumType

	items := pub.GetAll()
	for _, item := range items {
		appNumMap := item.(types.UuidToNum)
		if appNumMap.NumType != numType {
			continue
		}
		log.Functionf("appNumAllocatorInit found %v", appNumMap)
		appNum := appNumMap.Number
		baseID := appNumMap.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		baseMap := appNumBaseGet()
		if baseMap.IsSet(appNum) {
			log.Errorf("Bitmap is already set for %s num %d",
				baseID.String(), appNum)
			continue
		}
		log.Functionf("Reserving appNum %d for %s",
			appNum, baseID)
		baseMap.Set(appNum)
		// Clear InUse
		uuidtonum.UuidToNumFree(log, pub, baseID)
	}
	// In case zedrouter process restarted we fill in InUse from
	// AppNetworkStatus
	items = pubAppNetworkStatus.GetAll()
	for _, item := range items {
		status := item.(types.AppNetworkStatus)
		appNum := status.AppNum
		baseID := status.UUIDandVersion.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		baseMap := appNumBaseGet()
		if !baseMap.IsSet(appNum) {
			log.Fatalf("Bitmap is not set for %s num %d",
				baseID.String(), appNum)
			continue
		}
		log.Functionf("Marking InUse appNum %d for %s", appNum, baseID)
		// Set InUse
		uuidtonum.UuidToNumAllocate(log, pub, baseID, appNum,
			false, numType)
	}
}

// If an entry is not inUse and and its CreateTime were
// before the agent started, then we free it up.
func appNumAllocatorGC(ctx *zedrouterContext) {

	pub := ctx.pubUuidToNum
	numType := appNumType

	log.Functionf("appNumAllocatorGC")
	freedCount := 0
	items := pub.GetAll()
	for _, item := range items {
		appNumMap := item.(types.UuidToNum)
		if appNumMap.NumType != numType {
			continue
		}
		if appNumMap.InUse {
			continue
		}
		if appNumMap.CreateTime.After(ctx.agentStartTime) {
			continue
		}
		log.Functionf("appNumAllocatorGC: freeing %+v", appNumMap)
		appNumFree(ctx, appNumMap.UUID)
		freedCount++
	}
	log.Functionf("appNumAllocatorGC freed %d", freedCount)
}

func appNumAllocate(ctx *zedrouterContext, baseID uuid.UUID,
	isZedmanager bool) int {

	pub := ctx.pubUuidToNum
	numType := appNumType
	baseMap := appNumBaseGet()

	// Do we already have a number?
	appNum, err := uuidtonum.UuidToNumGet(log, pub, baseID,
		numType)
	if err == nil {
		log.Functionf("Found allocated appNum %d for %s", appNum,
			baseID)
		if !baseMap.IsSet(appNum) {
			log.Fatalf("Bitmap value(%d) is not set", appNum)
		}
		// Set InUse and update time
		uuidtonum.UuidToNumAllocate(log, pub, baseID, appNum,
			false, numType)
		return appNum
	}

	// Find a free number in bitmap; look for zero if isZedmanager
	if isZedmanager && !baseMap.IsSet(0) {
		appNum = 0
		log.Functionf("Allocating appNum %d for %s isZedmanager",
			appNum, baseID)
	} else {
		// XXX could look for non-0xFF bytes first for efficiency
		appNum = 0
		for i := 1; i < 256; i++ {
			if !baseMap.IsSet(i) {
				appNum = i
				log.Functionf("Allocating appNum %d for %s",
					appNum, baseID)
				break
			}
		}
		if appNum == 0 {
			log.Functionf("Failed to find free appNum for %s. Reusing!",
				baseID)
			oldBaseID, oldAppNum, err :=
				uuidtonum.UuidToNumGetOldestUnused(log, pub, numType)
			if err != nil {
				log.Fatal("All 255 appNums are in use!")
			}
			log.Functionf("Reuse found appNum %d for %s. Reusing!",
				oldAppNum, oldBaseID)
			uuidtonum.UuidToNumDelete(log, pub, oldBaseID)
			baseMap.Clear(oldAppNum)
			appNum = oldAppNum
		}
	}
	if baseMap.IsSet(appNum) {
		log.Fatalf("Bitmap is already set for %d", appNum)
	}
	baseMap.Set(appNum)
	uuidtonum.UuidToNumAllocate(log, pub, baseID, appNum, true,
		numType)
	return appNum
}

func appNumFree(ctx *zedrouterContext, baseID uuid.UUID) {

	pub := ctx.pubUuidToNum
	numType := appNumType
	appNum, err := uuidtonum.UuidToNumGet(log, pub, baseID, numType)
	if err != nil {
		log.Fatalf("num not found for %s",
			baseID.String())
	}
	baseMap := appNumBaseGet()
	// Check that number exists in the allocated numbers
	if !baseMap.IsSet(appNum) {
		log.Fatalf("Bitmap is not set for %d", appNum)
	}
	baseMap.Clear(appNum)
	uuidtonum.UuidToNumDelete(log, pub, baseID)
}

// returns base bitMap
func appNumBaseGet() *types.Bitmap {
	return &AllocReservedAppNumBits
}
