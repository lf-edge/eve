// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Allocate a small integer for each NetworkObject UUID.
// Persist the numbers across reboots using uuidtonum package
// When there are no free numbers then reuse the unused numbers.

package zedrouter

import (
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/uuidtonum"
)

var AllocReservedBridgeNumBits Bitmap

// Read the existing bridgeNums out of what we published/checkpointed.
// Also read what we have persisted before a reboot
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func bridgeNumAllocatorInit(ctx *zedrouterContext) {

	pubNetworkObjectStatus := ctx.pubNetworkObjectStatus
	pubUuidToNum := ctx.pubUuidToNum

	items := pubUuidToNum.GetAll()
	for key, st := range items {
		status := cast.CastUuidToNum(st)
		if status.Key() != key {
			log.Errorf("bridgeNumAllocatorInit key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		if status.NumType != "bridgeNum" {
			continue
		}
		log.Infof("bridgeNumAllocatorInit found %v\n", status)
		bridgeNum := status.Number
		uuid := status.UUID
		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		if AllocReservedBridgeNumBits.IsSet(bridgeNum) {
			log.Errorf("AllocReservedBridgeNums already set for %d\n",
				bridgeNum)
			continue
		}
		log.Infof("Reserving bridgeNum %d for %s\n", bridgeNum, uuid)
		AllocReservedBridgeNumBits.Set(bridgeNum)
		// Clear InUse
		uuidtonum.UuidToNumFree(ctx.pubUuidToNum, uuid)
	}
	// In case zedrouter process restarted we fill in InUse from
	// NetworkObjectStatus
	items = pubNetworkObjectStatus.GetAll()
	for key, st := range items {
		status := cast.CastNetworkObjectStatus(st)
		if status.Key() != key {
			log.Errorf("bridgeNumAllocatorInit key/UUID mismatch %s vs %s; ignored %+v\n",
				key, status.Key(), status)
			continue
		}
		bridgeNum := status.BridgeNum
		uuid := status.UUID

		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		// XXX however, on startup we are not likely to have any
		// config yet.
		if !AllocReservedBridgeNumBits.IsSet(bridgeNum) {
			log.Fatalf("AllocReservedBridgeNumBits not set for %s num %d\n",
				uuid.String(), bridgeNum)
			continue
		}
		log.Infof("Marking InUse bridgeNum %d for %s\n", bridgeNum, uuid)
		// Set InUse
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, bridgeNum,
			false, "bridgeNum")
	}
}

func bridgeNumAllocate(ctx *zedrouterContext, uuid uuid.UUID) int {

	// Do we already have a number?
	bridgeNum, err := uuidtonum.UuidToNumGet(ctx.pubUuidToNum, uuid,
		"bridgeNum")
	if err == nil {
		log.Infof("Found allocated bridgeNum %d for %s\n",
			bridgeNum, uuid)
		if !AllocReservedAppNumBits.IsSet(bridgeNum) {
			log.Fatalf("AllocReservedAppNumBits not set for %d\n",
				bridgeNum)
		}
		// Set InUse and update time
		uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, bridgeNum,
			false, "bridgeNum")
		return bridgeNum
	}

	// Find a free number in bitmap
	// XXX could look for non-0xFF bytes first for efficiency
	bridgeNum = 0
	for i := 1; i < 256; i++ {
		if !AllocReservedBridgeNumBits.IsSet(i) {
			bridgeNum = i
			log.Infof("Allocating bridgeNum %d for %s\n",
				bridgeNum, uuid)
			break
		}
	}
	if bridgeNum == 0 {
		log.Infof("Failed to find free bridgeNum for %s. Reusing!\n",
			uuid)
		log.Infof("Failed to find free bridgeNum for %s. Reusing!\n",
			uuid)
		uuid, bridgeNum, err := uuidtonum.UuidToNumGetOldestUnused(ctx.pubUuidToNum, "bridgeNum")
		if err != nil {
			log.Fatal("All 255 bridgeNums are in use!")
		}
		uuidtonum.UuidToNumDelete(ctx.pubUuidToNum, uuid)
		AllocReservedBridgeNumBits.Clear(bridgeNum)
	}
	if AllocReservedBridgeNumBits.IsSet(bridgeNum) {
		log.Fatalf("AllocReservedBridgeNums already set for %d\n",
			bridgeNum)
	}
	AllocReservedBridgeNumBits.Set(bridgeNum)
	uuidtonum.UuidToNumAllocate(ctx.pubUuidToNum, uuid, bridgeNum, true,
		"bridgeNum")
	return bridgeNum
}

func bridgeNumFree(ctx *zedrouterContext, uuid uuid.UUID) {

	bridgeNum, err := uuidtonum.UuidToNumGet(ctx.pubUuidToNum, uuid, "bridgeNum")
	if err != nil {
		log.Fatalf("bridgeNumFree: num not found for %s\n",
			uuid.String())
	}
	// Check that number exists in the allocated numbers
	if !AllocReservedBridgeNumBits.IsSet(bridgeNum) {
		log.Fatalf("bridgeNumFree: AllocReservedBridgeNumBits not set for %d\n",
			bridgeNum)
	}
	AllocReservedBridgeNumBits.Clear(bridgeNum)
	uuidtonum.UuidToNumDelete(ctx.pubUuidToNum, uuid)
}
