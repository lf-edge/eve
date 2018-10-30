// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Allocate a small integer for each application UUID.
// The number can not exceed 255 since we use the as IPv4 subnet numbers.
// Remember which UUIDs have which appnum's even after the number is freed so
// that a subsequent allocation is likely to get the same number; thus
// keep the allocated numbers in reserve.
// When there are no free numbers then reuse the reserved numbers.
// We try to give the application with IsZedmanager=true appnum zero.

package zedrouter

import (
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/uuidtonum"
)

// The allocated numbers
var AllocatedAppNum map[uuid.UUID]int

// The reserved numbers for uuids found it config or deleted.
var ReservedAppNum map[uuid.UUID]int

// Bitmap of the reserved and allocated
// Keeps 256 bits indexed by 0 to 255.
type Bitmap [32]byte

func (bits *Bitmap) IsSet(i int) bool { return bits[i/8]&(1<<uint(7-i%8)) != 0 }
func (bits *Bitmap) Set(i int)        { bits[i/8] |= 1 << uint(7-i%8) }
func (bits *Bitmap) Clear(i int)      { bits[i/8] &^= 1 << uint(7-i%8) }

var AllocReservedAppNums Bitmap

// Read the existing appNums out of what we published/checkpointed.
// Also read what we have persisted before a reboot
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func appNumAllocatorInit(ctx *zedrouterContext) {

	pubAppNetworkStatus := ctx.pubAppNetworkStatus
	pubUuidToNum := ctx.pubUuidToNum
	AllocatedAppNum = make(map[uuid.UUID]int)
	ReservedAppNum = make(map[uuid.UUID]int)

	items := pubUuidToNum.GetAll()
	for key, st := range items {
		status := cast.CastUuidToNum(st)
		if status.Key() != key {
			log.Errorf("appNumAllocatorInit key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		log.Infof("appNumAllocatorInit found %v\n", status)
		appNum := status.Number
		uuid := status.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		if AllocReservedAppNums.IsSet(appNum) {
			log.Errorf("AllocReservedAppNums already set for %d\n",
				appNum)
			continue
		}
		log.Infof("Reserving appNum %d for %s\n", appNum, uuid)
		ReservedAppNum[uuid] = appNum
		AllocReservedAppNums.Set(appNum)
	}
	items = pubAppNetworkStatus.GetAll()
	for key, st := range items {
		status := cast.CastAppNetworkStatus(st)
		if status.Key() != key {
			log.Errorf("appNumAllocatorInit key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		appNum := status.AppNum
		uuid := status.UUIDandVersion.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		if AllocReservedAppNums.IsSet(appNum) {
			log.Errorf("AllocReservedAppNums already set for %d\n",
				appNum)
			continue
		}
		log.Infof("Reserving appNum %d for %s\n", appNum, uuid)
		ReservedAppNum[uuid] = appNum
		AllocReservedAppNums.Set(appNum)
	}
}

func appNumAllocate(ctx *zedrouterContext,
	uuid uuid.UUID, isZedmanager bool) int {

	// Do we already have a number?
	appNum, ok := AllocatedAppNum[uuid]
	if ok {
		log.Infof("Found allocated appNum %d for %s\n", appNum, uuid)
		if !AllocReservedAppNums.IsSet(appNum) {
			log.Fatalf("AllocReservedAppNums not set for %d\n",
				appNum)
		}
		uuidtonum.UuidToNumUpdate(ctx.pubUuidToNum, uuid, appNum)
		return appNum
	}
	// Do we already have it in reserve?
	appNum, ok = ReservedAppNum[uuid]
	if ok {
		log.Infof("Found reserved appNum %d for %s\n", appNum, uuid)
		if !AllocReservedAppNums.IsSet(appNum) {
			log.Fatalf("AllocReservedAppNums not set for %d\n",
				appNum)
		}
		AllocatedAppNum[uuid] = appNum
		delete(ReservedAppNum, uuid)
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, appNum,
			false, "appNum")
		return appNum
	}

	// Find a free number in bitmap; look for zero if isZedmanager
	if isZedmanager && !AllocReservedAppNums.IsSet(0) {
		appNum = 0
		log.Infof("Allocating appNum %d for %s isZedmanager\n",
			appNum, uuid)
	} else {
		// XXX could look for non-0xFF bytes first for efficiency
		appNum = 0
		for i := 1; i < 256; i++ {
			if !AllocReservedAppNums.IsSet(i) {
				appNum = i
				log.Infof("Allocating appNum %d for %s\n",
					appNum, uuid)
				break
			}
		}
		if appNum == 0 {
			log.Infof("Failed to find free appNum for %s. Reusing!\n", uuid)
			// Unreserve first reserved
			for r, i := range ReservedAppNum {
				log.Infof("Unreserving %d for %s\n", i, r)
				delete(ReservedAppNum, r)
				AllocReservedAppNums.Clear(i)
				return appNumAllocate(ctx, uuid, isZedmanager)
			}
			log.Fatal("All 255 appNums are in use!")
		}
	}
	AllocatedAppNum[uuid] = appNum
	if AllocReservedAppNums.IsSet(appNum) {
		log.Fatalf("AllocReservedAppNums already set for %d\n",
			appNum)
	}
	AllocReservedAppNums.Set(appNum)
	uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, appNum, true,
		"appNum")
	return appNum
}

func appNumFree(ctx *zedrouterContext, uuid uuid.UUID) {

	// Check that number exists in the allocated numbers
	appNum, ok := AllocatedAppNum[uuid]
	reserved := false
	if !ok {
		appNum, ok = ReservedAppNum[uuid]
		if !ok {
			log.Fatalf("appNumFree: not for %s\n", uuid)
		}
		reserved = true
	}
	if !AllocReservedAppNums.IsSet(appNum) {
		log.Fatalf("AllocReservedAppNums not set for %d\n",
			appNum)
	}
	// Need to handle a free of a reserved number in which case
	// we have nothing to do since it remains reserved.
	if reserved {
		uuidtonum.UuidToNumFree(ctx.pubUuidToNum, uuid)
		return
	}

	_, ok = ReservedAppNum[uuid]
	if ok {
		log.Fatalf("appNumFree: already in reserved %s\n", uuid)
	}
	ReservedAppNum[uuid] = appNum
	delete(AllocatedAppNum, uuid)
	uuidtonum.UuidToNumFree(ctx.pubUuidToNum, uuid)
}
