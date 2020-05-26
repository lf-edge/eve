// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Wrapper with locking. Similar API to sync.map
// The Range callback function must not call functions
// which access the StringMap.
// XXX should we generalize to have Range copy the whole map?

package base

import (
	"sync"
)

type LockedStringMap struct {
	sync.RWMutex
	locked map[string]interface{}
}

func NewLockedStringMap() *LockedStringMap {
	return &LockedStringMap{locked: make(map[string]interface{})}
}

func (sm *LockedStringMap) Load(key string) (value interface{}, ok bool) {
	sm.RLock()
	result, ok := sm.locked[key]
	sm.RUnlock()
	return result, ok
}

func (sm *LockedStringMap) Delete(key string) {
	sm.Lock()
	delete(sm.locked, key)
	sm.Unlock()
}

func (sm *LockedStringMap) Store(key string, value interface{}) {
	sm.Lock()
	sm.locked[key] = value
	sm.Unlock()
}

// StrMapFunc :
type StrMapFunc func(key string, val interface{}) bool

func (sm *LockedStringMap) Range(callback StrMapFunc) {
	sm.RLock()
	for k, v := range sm.locked {
		if !callback(k, v) {
			break
		}
	}
	sm.RUnlock()
}
