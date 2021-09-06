// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Queue to work with objects with sorting by priority of type

package priorityQueue

import (
	"sync"
	"time"
)

type queueObject struct {
	lastTime time.Time
	obj      interface{}
}

//PriorityQueue contains objects with particular type and key
type PriorityQueue struct {
	objs                   map[interface{}]map[string]queueObject //map[type]map[key]queueObject
	count                  uint32
	priorityCheckFunctions []typePriorityCheck
	lock                   sync.Mutex
}

//typePriorityCheck returns true in case of find objType with high priority
type typePriorityCheck func(objType interface{}) bool

//InitQueue returns new PriorityQueue with defined priorityCheckFunctions
func InitQueue(priorityCheckFunctions ...typePriorityCheck) *PriorityQueue {
	//append with return first
	priorityCheckFunctions = append(priorityCheckFunctions, func(obj interface{}) bool {
		return true
	})
	return &PriorityQueue{
		objs:                   make(map[interface{}]map[string]queueObject),
		priorityCheckFunctions: priorityCheckFunctions,
	}
}

//GetCount returns current count of objects inside PriorityQueue
func (q *PriorityQueue) GetCount() uint32 {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.count
}

//Put adds or modify existing object of defined type
//will override existing ones if override set
func (q *PriorityQueue) Put(objType interface{}, key string, obj interface{}, override bool) {
	q.lock.Lock()
	defer q.lock.Unlock()
	if _, ok := q.objs[objType]; !ok {
		q.objs[objType] = make(map[string]queueObject)
	}
	if _, ok := q.objs[objType][key]; !ok {
		q.count++
	} else {
		if !override {
			return
		}
	}
	q.objs[objType][key] = queueObject{
		lastTime: time.Now(),
		obj:      obj,
	}
}

//Get returns key and object from queue with priority defined in priorityCheckFunctions
func (q *PriorityQueue) Get() (objType interface{}, key string, obj interface{}) {
	q.lock.Lock()
	defer q.lock.Unlock()
	for _, f := range q.priorityCheckFunctions {
		for t, objsMap := range q.objs {
			if f(t) {
				for key, val := range objsMap {
					obj = val.obj
					q.count--
					delete(objsMap, key)
					if len(objsMap) == 0 {
						delete(q.objs, t)
					}
					return t, key, obj
				}
			}
		}
	}
	return nil, "", nil
}

//Cleanup removes all objects comes before oldestTime
func (q *PriorityQueue) Cleanup(oldestTime time.Time) {
	q.lock.Lock()
	defer q.lock.Unlock()
	for t, objsMap := range q.objs {
		for k, v := range objsMap {
			if v.lastTime.Before(oldestTime) {
				delete(objsMap, k)
				q.count--
				if len(objsMap) == 0 {
					delete(q.objs, t)
				}
			}
		}
	}
}
