// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package generics

import "sync"

// LockedMap is a wrapper on map with locking API is similar to sync.Map
// difference is that sync.Map is optimized for two common use cases:
// (1) when the entry for a given key is only ever written once but read many times
// (2) when multiple goroutines read, write and overwrite entries for disjoint set of keys
// In these casees use sync.Map, in other cases consider using LockedMap
//
// LockedMap should be created by calling NewLockedMap()
type LockedMap[K comparable, V any] struct {
	sync.RWMutex
	locked map[K]V
}

// NewLockedMap returns initialized LockedMap struct
func NewLockedMap[K comparable, V any]() *LockedMap[K, V] {
	return &LockedMap[K, V]{
		locked: make(map[K]V),
	}
}

// Load returns value for given key; bool shows if map contains variable
func (lm *LockedMap[K, V]) Load(key K) (V, bool) {
	lm.RLock()
	result, ok := lm.locked[key]
	lm.RUnlock()
	return result, ok
}

// Delete removes value from map for given key
func (lm *LockedMap[K, V]) Delete(key K) {
	lm.Lock()
	delete(lm.locked, key)
	lm.Unlock()
}

// Store saves value for given key. Overrites previous value
func (lm *LockedMap[K, V]) Store(key K, value V) {
	lm.Lock()
	lm.locked[key] = value
	lm.Unlock()
}

// Keys return copy of keys for locked map
func (lm *LockedMap[K, V]) Keys() []K {
	lm.RLock()
	defer lm.RUnlock()

	result := make([]K, 0, len(lm.locked))
	for k := range lm.locked {
		result = append(result, k)
	}

	return result
}

// LockedMapFunc is function signature for Range function
type LockedMapFunc[K comparable, V any] func(K, V) bool

// Range iterates over map and applies callback to every element
// iteration stops if callback returns false.
// callback function is not allowed to do any changes on map
// (Store, Delete or Load) since that can deadlock
func (lm *LockedMap[K, V]) Range(callback LockedMapFunc[K, V]) {
	lm.RLock()
	for k, v := range lm.locked {
		if !callback(k, v) {
			break
		}
	}
	lm.RUnlock()
}

// LockedMapApplyFunc is function signature for ApplyOrStore function
type LockedMapApplyFunc[V any] func(V) V

// ApplyOrStore is used to perform atomic operations, where the operation
// is performed by the applyFn function. If the key does not exist in the map
// then defaultVal will be stored. Otherwise the entry for the key will be updated.
// returns true if the key existed when the function was called
func (lm *LockedMap[K, V]) ApplyOrStore(key K, applyFn LockedMapApplyFunc[V], defaultVal V) bool {
	lm.Lock()
	defer lm.Unlock()

	applied := false

	if v, ok := lm.locked[key]; ok {
		lm.locked[key] = applyFn(v)
		applied = true
	} else {
		lm.locked[key] = defaultVal
	}

	return applied
}
