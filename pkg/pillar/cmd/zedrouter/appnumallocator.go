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
	log "github.com/sirupsen/logrus"
)

// Bitmap of the reserved and allocated
// Keeps 256 bits indexed by 0 to 255.
type Bitmap [32]byte

func (bits *Bitmap) IsSet(i int) bool { return bits[i/8]&(1<<uint(7-i%8)) != 0 }
func (bits *Bitmap) Set(i int)        { bits[i/8] |= 1 << uint(7-i%8) }
func (bits *Bitmap) Clear(i int)      { bits[i/8] &^= 1 << uint(7-i%8) }

var AllocReservedAppNumBits Bitmap

// Read the existing appNums out of what we published/checkpointed.
// Also read what we have persisted before a reboot
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func appNumAllocatorInit(ctx *zedrouterContext) {

	pubAppNetworkStatus := ctx.pubAppNetworkStatus
	pubUuidToNum := ctx.pubUuidToNum

	items := pubUuidToNum.GetAll()
	for _, st := range items {
		status := st.(types.UuidToNum)
		if status.NumType != "appNum" {
			continue
		}
		log.Infof("appNumAllocatorInit found %v\n", status)
		appNum := status.Number
		uuid := status.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		if AllocReservedAppNumBits.IsSet(appNum) {
			log.Errorf("AllocReservedAppNumBits already set for %s num %d\n",
				uuid.String(), appNum)
			continue
		}
		log.Infof("Reserving appNum %d for %s\n", appNum, uuid)
		AllocReservedAppNumBits.Set(appNum)
		// Clear InUse
		uuidtonum.UuidToNumFree(ctx.pubUuidToNum, uuid)
	}
	// In case zedrouter process restarted we fill in InUse from
	// AppNetworkStatus
	items = pubAppNetworkStatus.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		appNum := status.AppNum
		uuid := status.UUIDandVersion.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		if !AllocReservedAppNumBits.IsSet(appNum) {
			log.Fatalf("AllocReservedAppNumBits not set for %s num %d\n",
				uuid.String(), appNum)
			continue
		}
		log.Infof("Marking InUse appNum %d for %s\n", appNum, uuid)
		// Set InUse
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, appNum,
			false, "appNum")
	}
}

// If an entry is not inUse and and its CreateTime were
// before the agent started, then we free it up.
func appNumAllocatorGC(ctx *zedrouterContext) {

	pubUuidToNum := ctx.pubUuidToNum

	log.Infof("appNumAllocatorGC")
	freedCount := 0
	items := pubUuidToNum.GetAll()
	for _, st := range items {
		status := st.(types.UuidToNum)
		if status.NumType != "appNum" {
			continue
		}
		if status.InUse {
			continue
		}
		if status.CreateTime.After(ctx.agentStartTime) {
			continue
		}
		log.Infof("appNumAllocatorGC: freeing %+v", status)
		appNumFree(ctx, status.UUID)
		freedCount++
	}
	log.Infof("appNumAllocatorGC freed %d", freedCount)
}

func appNumAllocate(ctx *zedrouterContext,
	uuid uuid.UUID, isZedmanager bool) int {

	// Do we already have a number?
	appNum, err := uuidtonum.UuidToNumGet(ctx.pubUuidToNum, uuid, "appNum")
	if err == nil {
		log.Infof("Found allocated appNum %d for %s\n", appNum, uuid)
		if !AllocReservedAppNumBits.IsSet(appNum) {
			log.Fatalf("AllocReservedAppNumBits not set for %d\n",
				appNum)
		}
		// Set InUse and update time
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, appNum,
			false, "appNum")
		return appNum
	}

	// Find a free number in bitmap; look for zero if isZedmanager
	if isZedmanager && !AllocReservedAppNumBits.IsSet(0) {
		appNum = 0
		log.Infof("Allocating appNum %d for %s isZedmanager\n",
			appNum, uuid)
	} else {
		// XXX could look for non-0xFF bytes first for efficiency
		appNum = 0
		for i := 1; i < 256; i++ {
			if !AllocReservedAppNumBits.IsSet(i) {
				appNum = i
				log.Infof("Allocating appNum %d for %s\n",
					appNum, uuid)
				break
			}
		}
		if appNum == 0 {
			log.Infof("Failed to find free appNum for %s. Reusing!\n",
				uuid)
			oldUuid, oldAppNum, err := uuidtonum.UuidToNumGetOldestUnused(ctx.pubUuidToNum, "appNum")
			if err != nil {
				log.Fatal("All 255 appNums are in use!")
			}
			log.Infof("Reuse found appNum %d for %s. Reusing!\n",
				oldAppNum, oldUuid)
			uuidtonum.UuidToNumDelete(ctx.pubUuidToNum, oldUuid)
			AllocReservedAppNumBits.Clear(oldAppNum)
			appNum = oldAppNum
		}
	}
	if AllocReservedAppNumBits.IsSet(appNum) {
		log.Fatalf("AllocReservedAppNumBits already set for %d\n",
			appNum)
	}
	AllocReservedAppNumBits.Set(appNum)
	uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, appNum, true,
		"appNum")
	return appNum
}

func appNumFree(ctx *zedrouterContext, uuid uuid.UUID) {

	appNum, err := uuidtonum.UuidToNumGet(ctx.pubUuidToNum, uuid, "appNum")
	if err != nil {
		log.Fatalf("appNumFree: num not found for %s\n",
			uuid.String())
	}
	// Check that number exists in the allocated numbers
	if !AllocReservedAppNumBits.IsSet(appNum) {
		log.Fatalf("appNumFree: AllocReservedAppNumBits not set for %d\n",
			appNum)
	}
	AllocReservedAppNumBits.Clear(appNum)
	uuidtonum.UuidToNumDelete(ctx.pubUuidToNum, uuid)
}
