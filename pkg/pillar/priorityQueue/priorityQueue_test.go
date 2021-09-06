// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package priorityQueue

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWithoutDefinedPriority(t *testing.T) {
	q := InitQueue()
	q.Put("t1", "k1", "v1", true)
	q.Put("t2", "k1", "v1", true)
	_, k, v := q.Get()
	assert.Equal(t, "k1", k)
	assert.Equal(t, "v1", v)
	assert.Equal(t, uint32(1), q.GetCount())
	_, k, v = q.Get()
	assert.Equal(t, "k1", k)
	assert.Equal(t, "v1", v)
	assert.Equal(t, uint32(0), q.GetCount())
}

func TestWithDefinedPriority(t *testing.T) {
	priorityCheckFunction := func(objType interface{}) bool {
		// priority for type "t2"
		if t, ok := objType.(string); ok && t == "t2" {
			return true
		}
		return false
	}
	q := InitQueue(priorityCheckFunction)
	q.Put("t1", "k1", "v1", true)
	q.Put("t2", "k2", "v2", true)
	objType, k, v := q.Get()
	assert.Equal(t, "t2", objType)
	assert.Equal(t, "k2", k)
	assert.Equal(t, "v2", v)
	assert.Equal(t, uint32(1), q.GetCount())
	objType, k, v = q.Get()
	assert.Equal(t, "t1", objType)
	assert.Equal(t, "k1", k)
	assert.Equal(t, "v1", v)
	assert.Equal(t, uint32(0), q.GetCount())
}

func TestOverride(t *testing.T) {
	q := InitQueue()
	q.Put("t1", "k1", "v1", true)
	q.Put("t1", "k1", "v2", true)
	q.Put("t1", "k1", "v3", false)
	objType, k, v := q.Get()
	assert.Equal(t, "t1", objType)
	assert.Equal(t, "k1", k)
	assert.Equal(t, "v2", v)
	assert.Equal(t, uint32(0), q.GetCount())
}

func TestAsync(t *testing.T) {
	q := InitQueue()
	go func() {
		for i := 0; i < 10; i++ {
			q.Put(strconv.Itoa(i), strconv.Itoa(i), strconv.Itoa(i), true)
		}
	}()
	expectedEnd := time.Now().Add(10 * time.Second)
	for i := 0; i < 10; {
		objType, k, v := q.Get()
		if v != nil {
			assert.Equal(t, k, v)
			assert.Equal(t, objType, v)
			i++
		}
		if time.Now().After(expectedEnd) {
			t.Error("timeout")
			return
		}
	}
}

func TestCleanup(t *testing.T) {
	q := InitQueue()
	q.Put("t1", "k1", "v1", true)
	q.Put("t1", "k1", "v2", true)
	q.Put("t1", "k1", "v3", false)
	time.Sleep(time.Second)
	q.Cleanup(time.Now())
	assert.Equal(t, uint32(0), q.GetCount())
}
