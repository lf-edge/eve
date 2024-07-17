// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package objtonum allows to allocate and assign an integer number to an object.
// Object can be any abstract entity. In EVE this can be for example: edge application,
// network bridge, network interface, etc.
// The assigned numbers can be published/persisted.
package objtonum

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// Allocator allocates and maps *unique* numbers to objects.
type Allocator struct {
	log            *base.LogObject
	numAlloc       NumberAllocator
	storage        Map
	allocatedCount int
	reservedCount  int
}

// NewAllocator creates new Allocator.
// Allocated Object->Number pairs are stored inside the given map.
// Allocator becomes sole owner of the map (it should not be manipulated outside
// the allocator or used for another allocator)
func NewAllocator(log *base.LogObject, numAlloc NumberAllocator, storage Map) (*Allocator, error) {
	// Sync numAlloc with already stored allocations.
	if err := numAlloc.FreeAll(); err != nil {
		return nil, err
	}
	var err error
	var allocatedCount, reservedCount int
	storage.Iterate(func(key ObjKey, number int, onlyReserved bool,
		createdAt, lastUpdatedAt time.Time) (stop bool) {
		_, err = numAlloc.Allocate(RequireNumber{Number: number})
		if err != nil {
			stop = true
		}
		if onlyReserved {
			reservedCount++
		} else {
			allocatedCount++
		}
		return
	})
	return &Allocator{
		log:            log,
		numAlloc:       numAlloc,
		storage:        storage,
		allocatedCount: allocatedCount,
		reservedCount:  reservedCount,
	}, nil
}

// GetOrAllocate returns for a given object either an already allocated/reserved number
// or allocates a new one. Previously reserved number becomes fully allocated.
// If there is no free number left but there are some reserved, it will steal number
// from the oldest reservation.
func (a *Allocator) GetOrAllocate(key ObjKey, allocOpts ...AllocOpt) (number int, err error) {
	var reqNumber *RequireNumber // nil if function can allocate any free number
	for _, allocOpt := range allocOpts {
		if rn, ok := allocOpt.(RequireNumber); ok {
			reqNumber = &rn
		}
	}
	var onlyReserved bool
	number, onlyReserved, err = a.storage.Get(key)
	if err == nil {
		if reqNumber != nil && reqNumber.Number != number {
			return 0, fmt.Errorf(
				"required number for key %s is %d but already allocated is %d",
				key.Key(), reqNumber.Number, number)
		}
		// If it was only reserved mark it as fully allocated.
		// Also refresh the lastUpdateAt timestamp.
		err = a.storage.Assign(key, number, false)
		if err == nil && onlyReserved {
			a.reservedCount--
			a.allocatedCount++
		}
		return number, err
	}
	// Find a free number to allocate.
	number, err = a.numAlloc.Allocate(allocOpts...)
	if err == nil {
		err = a.storage.Assign(key, number, true)
		if err == nil {
			a.allocatedCount++
		} else {
			// Failed to assign, try to release the number back.
			_ = a.numAlloc.Free(number)
		}
		return number, err
	}
	// Steal number from the oldest reserved-only number, if there is any.
	type objNum struct {
		key           ObjKey
		number        int
		lastUpdatedAt time.Time
	}
	var oldestReserved *objNum
	a.storage.Iterate(func(key ObjKey, number int, onlyReserved bool,
		createdAt, lastUpdatedAt time.Time) (stop bool) {
		if onlyReserved {
			if oldestReserved == nil ||
				oldestReserved.lastUpdatedAt.After(lastUpdatedAt) {
				oldestReserved = &objNum{
					key:           key,
					number:        number,
					lastUpdatedAt: lastUpdatedAt,
				}
			}
		}
		return
	})
	if oldestReserved != nil {
		if err = a.storage.Delete(oldestReserved.key, false); err != nil {
			return 0, err
		}
		a.log.Tracef("Stealing reserved number from old key %s for new key %s",
			oldestReserved.key, key)
		a.reservedCount--
		err = a.storage.Assign(key, oldestReserved.number, true)
		if err == nil {
			a.allocatedCount++
		} else {
			a.log.Tracef("Failed to steal number from old key %s for new key %s: %v",
				oldestReserved.key, key, err)
			// Stealing failed and furthermore we lost one reservation.
			_ = a.numAlloc.Free(oldestReserved.number)
			return 0, err
		}
		return oldestReserved.number, nil
	}
	return 0, fmt.Errorf("no free number available")
}

// AllocatedCount returns the count of allocated and reserved-only object numbers.
func (a *Allocator) AllocatedCount() (allocatedCount, reservedCount int) {
	return a.allocatedCount, a.reservedCount
}

// Free either fully removes number from an object, or keeps the pair but marks it as reserved.
// Note that reserved number will be used by the next GetOrAllocate for this object,
// but a reservation may as well be removed when allocator runs out of numbers to allocate from.
func (a *Allocator) Free(key ObjKey, keepReserved bool) error {
	number, wasReserved, err := a.storage.Get(key)
	if err != nil {
		return err
	}
	if !keepReserved {
		if err = a.numAlloc.Free(number); err != nil {
			return err
		}
	}
	err = a.storage.Delete(key, keepReserved)
	if err == nil {
		if wasReserved {
			if !keepReserved {
				a.reservedCount--
			}
		} else {
			a.allocatedCount--
			if keepReserved {
				a.reservedCount++
			}
		}
	} else if !keepReserved {
		// Try to revert it back.
		_, _ = a.numAlloc.Allocate(RequireNumber{number})
	}
	return err
}

// FreeMultiple applies Free operation on a subset of objects.
func (a *Allocator) FreeMultiple(selectKey ObjKeySelector, keepReserved bool) (err error) {
	a.storage.Iterate(func(key ObjKey, number int, onlyReserved bool,
		createdAt, lastUpdatedAt time.Time) (stop bool) {
		if selectKey(key) {
			err = a.Free(key, keepReserved)
			if err != nil {
				stop = true
			}
		}
		return
	})
	return err
}

// GC = garbage collection. The function removes all reservations (not full allocations)
// that originated from before the given time.
func (a *Allocator) GC(createdBefore time.Time) error {
	var err error
	var freed []ObjKey
	a.storage.Iterate(func(key ObjKey, number int, onlyReserved bool,
		createdAt, lastUpdatedAt time.Time) (stop bool) {
		if onlyReserved && createdAt.Before(createdBefore) {
			err = a.Free(key, false)
			if err != nil {
				stop = true
			}
			freed = append(freed, key)
		}
		return
	})
	a.log.Tracef("GC removed reservations for keys: %v", freed)
	return err
}

// NumberAllocator allows to allocate a not yet allocated number from a set of integers.
type NumberAllocator interface {
	// IsAllocated returns true if the given number is already allocated.
	IsAllocated(number int) bool
	// Allocate tries to allocate a new number.
	// Returns error if there is are no numbers left to allocate from
	// or allocOpts cannot be satisfied.
	Allocate(allocOpts ...AllocOpt) (number int, err error)
	// Free marks the number as available for future allocation.
	Free(number int) error
	// FreeAll marks all numbers in the set as free for allocation.
	FreeAll() error
}

// AllocOpt allows to customize the process of number allocation.
type AllocOpt interface {
	isAllocOpt()
}

// AllocStrategy : strategy to follow by NumberAllocator when allocating a number.
type AllocStrategy int

func (AllocStrategy) isAllocOpt() {}

const (
	// LowestFree : select smallest free number.
	LowestFree AllocStrategy = iota
	// HighestFree : select highest free number.
	HighestFree
	// RandomFree : randomly select one of the free numbers.
	RandomFree
)

// RequireNumber : tries to specifically allocate the given number.
// Will fail if this number is already allocated.
type RequireNumber struct {
	Number int
}

func (RequireNumber) isAllocOpt() {}

// ByteAllocator allocates numbers from the range <0,255> or <1,255>.
type ByteAllocator struct {
	bitmap      bitmap
	allocCount  int
	withZeroVal bool
}

// ByteAllocatorMaxNum : maximum number that can be allocated with ByteAllocator.
const ByteAllocatorMaxNum = 255

// NewByteAllocator is a constructor for ByteAllocator.
func NewByteAllocator(withZeroVal bool) *ByteAllocator {
	return &ByteAllocator{
		bitmap:      bitmap{},
		allocCount:  0,
		withZeroVal: withZeroVal,
	}
}

// IsAllocated returns true if the given number is already allocated.
func (ba *ByteAllocator) IsAllocated(number int) bool {
	return ba.bitmap.IsSet(number)
}

// Allocate tries to allocate a new number.
func (ba *ByteAllocator) Allocate(allocOpts ...AllocOpt) (number int, err error) {
	var minNum int
	if !ba.withZeroVal {
		minNum = 1
	}
	freeCount := ByteAllocatorMaxNum - minNum + 1 - ba.allocCount
	if freeCount == 0 {
		return 0, fmt.Errorf("no free number left")
	}
	strategy := LowestFree // default strategy
	for _, allocOpt := range allocOpts {
		switch opt := allocOpt.(type) {
		case RequireNumber:
			if opt.Number < minNum || opt.Number > ByteAllocatorMaxNum {
				return 0, fmt.Errorf("required number is out of range")
			}
			reqNumber := opt.Number
			if ba.IsAllocated(reqNumber) {
				return 0, fmt.Errorf("required number %d is already allocated", reqNumber)
			}
			ba.bitmap.Set(reqNumber)
			ba.allocCount++
			return reqNumber, nil
		case AllocStrategy:
			strategy = opt
		}
	}
	switch strategy {
	case LowestFree:
		for i := minNum; i < 256; i++ {
			if !ba.IsAllocated(i) {
				ba.bitmap.Set(i)
				ba.allocCount++
				return i, nil
			}
		}
	case HighestFree:
		for i := ByteAllocatorMaxNum; i >= minNum; i-- {
			if !ba.IsAllocated(i) {
				ba.bitmap.Set(i)
				ba.allocCount++
				return i, nil
			}
		}
	case RandomFree:
		// Take 1st or 2nd or ... free number.
		freeNumIdx := (rand.Int() % freeCount) + 1
		for i := minNum; i < 256; i++ {
			if !ba.IsAllocated(i) {
				freeNumIdx--
				if freeNumIdx == 0 {
					ba.bitmap.Set(i)
					ba.allocCount++
					return i, nil
				}
			}
		}
	}
	// unreachable
	return 0, nil
}

// Free marks the number as available for future allocation.
func (ba *ByteAllocator) Free(number int) error {
	if !ba.IsAllocated(number) {
		return fmt.Errorf("number %d is not allocated", number)
	}
	ba.bitmap.Clear(number)
	ba.allocCount--
	return nil
}

// FreeAll marks all numbers in the set as free for allocation.
func (ba *ByteAllocator) FreeAll() error {
	ba.bitmap = bitmap{}
	ba.allocCount = 0
	return nil
}

// bitmap of allocated numbers in the range 0 to 255.
type bitmap [32]byte

// IsSet return true if i-th bit is set.
func (bits *bitmap) IsSet(i int) bool {
	return bits[i/8]&(1<<uint(7-i%8)) != 0
}

// Set the bit value
func (bits *bitmap) Set(i int) {
	bits[i/8] |= 1 << uint(7-i%8)
}

// Clear the bit value
func (bits *bitmap) Clear(i int) {
	bits[i/8] &^= 1 << uint(7-i%8)
}
