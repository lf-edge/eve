// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Allocate a small integer for each application UUID.
// The number can not exceed 255 since we use the as IPv4 subnet numbers.
// Remember which UUIDs have which appnum's even after the number is freed so
// that a subsequent allocation is likely to get the same number; thus
// keep the allocated numbers in reserve.
// When there are no free numbers then reuse the reserved numbers.
// We try to give the application with IsZedmanager=true appnum zero.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/satori/go.uuid"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"os"
	"strings"
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


// Read the existing appNums out of statusDir
// Store in reserved map since we will be asked to allocate them later.
// Set bit in bitmap.
func appNumAllocatorInit(statusDir string, configDir string) {
	AllocatedAppNum = make(map[uuid.UUID]int)
	ReservedAppNum = make(map[uuid.UUID]int)

	statusFiles, err := ioutil.ReadDir(statusDir)
	if err != nil {
		log.Fatal(err, ": ", statusDir)
	}

	for _, statusFile := range statusFiles {
		fileName := statusFile.Name()
		if !strings.HasSuffix(fileName, ".json") {
			log.Printf("Ignoring file <%s>\n", fileName)
			continue
		}
		sb, err := ioutil.ReadFile(statusDir + "/" + fileName)
		if err != nil {
			log.Printf("%s for %s\n", err, fileName)
			continue
		}
		status := types.AppNetworkStatus{}
		if err := json.Unmarshal(sb, &status); err != nil {
			log.Printf("%s AppNetworkStatus file: %s\n",
				err, fileName)
			continue
		}
		uuid := status.UUIDandVersion.UUID
		if uuid.String()+".json" != fileName {
			log.Printf("Mismatch between filename and contained uuid: %s vs. %s\n",
				fileName, uuid.String())
			continue
		}
		appNum := status.AppNum
		// If we have a config for the UUID we should mark it as
		// allocated; otherwise mark it as reserved.
		if _, err := os.Stat(configDir +"/" + fileName); err != nil {
			fmt.Printf("Reserving appNum %d for %s\n", appNum, uuid)
			ReservedAppNum[uuid] = appNum
		} else {
			fmt.Printf("Allocating appNum %d for %s\n",
				appNum, uuid)
			AllocatedAppNum[uuid] = appNum
		}
		if AllocReservedAppNums.IsSet(appNum) {
			panic(fmt.Sprintf("AllocReservedAppNums already set for %d\n",
				appNum))
		}
		AllocReservedAppNums.Set(appNum)
	}
}

func appNumAllocate(uuid uuid.UUID, isZedmanager bool) int {
	// Do we already have a number?     
	appNum, ok := AllocatedAppNum[uuid]
	if ok {
		fmt.Printf("Found allocated appNum %d for %s\n", appNum, uuid)
		if !AllocReservedAppNums.IsSet(appNum) {
			panic(fmt.Sprintf("AllocReservedAppNums not set for %d\n", appNum))
		}
		return appNum
	}
	// Do we already have it in reserve?
	appNum, ok = ReservedAppNum[uuid]
	if ok {
		fmt.Printf("Found reserved appNum %d for %s\n", appNum, uuid)
		if !AllocReservedAppNums.IsSet(appNum) {
			panic(fmt.Sprintf("AllocReservedAppNums not set for %d\n", appNum))
		}
		AllocatedAppNum[uuid] = appNum
		delete(ReservedAppNum, uuid)
		return appNum
	}

	// Find a free number in bitmap; look for zero if isZedmanager
	if isZedmanager && !AllocReservedAppNums.IsSet(0) {
		appNum = 0
		fmt.Printf("Allocating appNum %d for %s isZedmanager\n",
			appNum, uuid)
	} else {
		// XXX could look for non-0xFF bytes first for efficiency
		appNum = 0
		for i := 1; i < 256; i++ {
			if !AllocReservedAppNums.IsSet(i) {
				appNum = i
				fmt.Printf("Allocating appNum %d for %s\n",
					appNum, uuid)
				break
			}
		}
		if appNum == 0 {
			fmt.Printf("Failed to find free appNum for %s. Reusing!\n", uuid)
			// Unreserve first reserved
			for r, i := range ReservedAppNum {
				fmt.Printf("Unreserving %d for %s\n", i, r)
				delete(ReservedAppNum, r)
				AllocReservedAppNums.Clear(i)
				return appNumAllocate(uuid, isZedmanager)
			}
			panic("All 255 appNums are in use!")
		}
	}
	AllocatedAppNum[uuid] = appNum
	if AllocReservedAppNums.IsSet(appNum) {
		panic(fmt.Sprintf("AllocReservedAppNums already set for %d\n",
			appNum))
	}
	AllocReservedAppNums.Set(appNum)
	return appNum
}

func appNumFree(uuid uuid.UUID) {
	// Check that number exists in the allocated numbers     
	appNum, ok := AllocatedAppNum[uuid]
	reserved := false
	if !ok {
		appNum, ok = ReservedAppNum[uuid]
		if !ok {
			panic(fmt.Sprintf("appNumFree: not for %s\n", uuid))
		}
		reserved = true
	}
	if !AllocReservedAppNums.IsSet(appNum) {
		panic(fmt.Sprintf("AllocReservedAppNums not set for %d\n",
		appNum))
	}
	// Need to handle a free of a reserved number in which case
	// we have nothing to do since it remains reserved.
	if reserved {
		return
	}
	
	_, ok = ReservedAppNum[uuid]
	if ok {
		panic(fmt.Sprintf("appNumFree: already in reserved %s\n", uuid))
	}
	ReservedAppNum[uuid] = appNum
	delete(AllocatedAppNum, uuid)
}
