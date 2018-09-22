// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Allocate a small integer for each application UUID.
// Remember which UUIDs have which bridgeNum's even after the number is freed so
// that a subsequent allocation is likely to get the same number; thus
// keep the allocated numbers in reserve.
// When there are no free numbers then reuse the reserved numbers.

package zedrouter

import (
	"fmt"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
)

// The allocated numbers
var AllocatedBridgeNum map[uuid.UUID]int

// The reserved numbers for uuids found it config or deleted.
var ReservedBridgeNum map[uuid.UUID]int

var AllocReservedBridgeNums Bitmap

// Read the existing bridgeNums out of what we published/checkpointed.
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func bridgeNumAllocatorInit(pubNetworkObjectStatus *pubsub.Publication) {
	AllocatedBridgeNum = make(map[uuid.UUID]int)
	ReservedBridgeNum = make(map[uuid.UUID]int)

	items := pubNetworkObjectStatus.GetAll()
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
		log.Infof("Reserving bridgeNum %d for %s\n", bridgeNum, uuid)
		ReservedBridgeNum[uuid] = bridgeNum
		if AllocReservedBridgeNums.IsSet(bridgeNum) {
			panic(fmt.Sprintf("AllocReservedBridgeNums already set for %d\n",
				bridgeNum))
		}
		AllocReservedBridgeNums.Set(bridgeNum)
	}
}

func bridgeNumAllocate(uuid uuid.UUID) int {
	// Do we already have a number?
	bridgeNum, ok := AllocatedBridgeNum[uuid]
	if ok {
		log.Infof("Found allocated bridgeNum %d for %s\n", bridgeNum, uuid)
		if !AllocReservedBridgeNums.IsSet(bridgeNum) {
			panic(fmt.Sprintf("AllocReservedBridgeNums not set for %d\n", bridgeNum))
		}
		return bridgeNum
	}
	// Do we already have it in reserve?
	bridgeNum, ok = ReservedBridgeNum[uuid]
	if ok {
		log.Infof("Found reserved bridgeNum %d for %s\n", bridgeNum, uuid)
		if !AllocReservedBridgeNums.IsSet(bridgeNum) {
			panic(fmt.Sprintf("AllocReservedBridgeNums not set for %d\n", bridgeNum))
		}
		AllocatedBridgeNum[uuid] = bridgeNum
		delete(ReservedBridgeNum, uuid)
		return bridgeNum
	}

	// Find a free number in bitmap
	// XXX could look for non-0xFF bytes first for efficiency
	bridgeNum = 0
	for i := 1; i < 256; i++ {
		if !AllocReservedBridgeNums.IsSet(i) {
			bridgeNum = i
			log.Infof("Allocating bridgeNum %d for %s\n",
				bridgeNum, uuid)
			break
		}
	}
	if bridgeNum == 0 {
		log.Infof("Failed to find free bridgeNum for %s. Reusing!\n",
			uuid)
		// Unreserve first reserved
		for r, i := range ReservedBridgeNum {
			log.Infof("Unreserving %d for %s\n", i, r)
			delete(ReservedBridgeNum, r)
			AllocReservedBridgeNums.Clear(i)
			return bridgeNumAllocate(uuid)
		}
		panic("All 255 bridgeNums are in use!")
	}
	AllocatedBridgeNum[uuid] = bridgeNum
	if AllocReservedBridgeNums.IsSet(bridgeNum) {
		panic(fmt.Sprintf("AllocReservedBridgeNums already set for %d\n",
			bridgeNum))
	}
	AllocReservedBridgeNums.Set(bridgeNum)
	return bridgeNum
}

func bridgeNumFree(uuid uuid.UUID) {
	// Check that number exists in the allocated numbers
	bridgeNum, ok := AllocatedBridgeNum[uuid]
	reserved := false
	if !ok {
		bridgeNum, ok = ReservedBridgeNum[uuid]
		if !ok {
			panic(fmt.Sprintf("bridgeNumFree: not for %s\n", uuid))
		}
		reserved = true
	}
	if !AllocReservedBridgeNums.IsSet(bridgeNum) {
		panic(fmt.Sprintf("AllocReservedBridgeNums not set for %d\n",
			bridgeNum))
	}
	// Need to handle a free of a reserved number in which case
	// we have nothing to do since it remains reserved.
	if reserved {
		return
	}

	_, ok = ReservedBridgeNum[uuid]
	if ok {
		panic(fmt.Sprintf("bridgeNumFree: already in reserved %s\n", uuid))
	}
	ReservedBridgeNum[uuid] = bridgeNum
	delete(AllocatedBridgeNum, uuid)
}
