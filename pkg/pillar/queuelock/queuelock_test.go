// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// queuelock is a package which implements a locking queue
// where only one operation is performed at a time.
// This is at some level analogous to a channel with a single worker
// reading work from the channel, with the key difference is that
// the queuelock compresses multiple identical requests.
// That is done by identifying each piece of work with a unique
// enum value.

package queuelock

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// enum values for work
type myWork uint

const (
	myWorkUpdate = uint(iota) // enum for key scheme
	myWorkValidate
	myWorkTest
	myWorkRestart
)

func assertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f()
}

func TestExtraExit(t *testing.T) {
	h := NewQueueLock()
	assert.NotNil(t, h)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())

	exitWithoutEnter := func() { h.Exit(myWorkValidate) }
	assertPanic(t, exitWithoutEnter)
}

func TestBadExit(t *testing.T) {
	h := NewQueueLock()
	assert.NotNil(t, h)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())

	entered := h.Enter(myWorkUpdate)
	assert.True(t, entered)
	assert.Equal(t, 0, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	wrongExit := func() { h.Exit(myWorkValidate) }
	assertPanic(t, wrongExit)
}

func TestOne(t *testing.T) {
	h := NewQueueLock()
	assert.NotNil(t, h)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())

	entered := h.Enter(myWorkUpdate)
	assert.True(t, entered)
	assert.Equal(t, 0, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	h.Exit(myWorkUpdate)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())
}

// Returns work, ok from channel
func tryChannel(h *Handle) (uint, bool) {
	select {
	case work := <-h.MsgChan():
		return work, true
	default:
		return uint(0), false
	}
}

func TestTwo(t *testing.T) {
	h := NewQueueLock()
	assert.NotNil(t, h)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())

	e1 := h.Enter(myWorkUpdate)
	assert.True(t, e1)
	assert.Equal(t, 0, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	e2 := h.Enter(myWorkTest)
	assert.False(t, e2)
	assert.Equal(t, 1, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	h.Exit(myWorkUpdate)
	assert.Equal(t, 0, h.NumWaiters()) // Handed to channel
	assert.False(t, h.IsBusy())

	work, ok := tryChannel(h)
	assert.True(t, ok)
	assert.Equal(t, myWorkTest, work)
	e3 := h.Enter(work)
	assert.True(t, e3)
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(work))
	h.Exit(work)
}

func TestThree(t *testing.T) {
	h := NewQueueLock()
	assert.NotNil(t, h)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())

	e1 := h.Enter(myWorkUpdate)
	assert.True(t, e1)
	assert.Equal(t, 0, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	e2 := h.Enter(myWorkTest)
	assert.False(t, e2)
	assert.Equal(t, 1, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	e3 := h.Enter(myWorkValidate)
	assert.False(t, e3)
	assert.Equal(t, 2, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	h.Exit(myWorkUpdate)
	assert.Equal(t, 1, h.NumWaiters()) // One handed to channel
	assert.False(t, h.IsBusy())

	work, ok := tryChannel(h)
	assert.True(t, ok)
	assert.Equal(t, myWorkTest, work)
	e4 := h.Enter(work)
	assert.True(t, e4)
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(work))
	h.Exit(work)

	assert.False(t, h.IsBusy())
	assert.Equal(t, 0, h.NumWaiters()) // Last one sent to channel

	work, ok = tryChannel(h)
	assert.True(t, ok)
	assert.Equal(t, myWorkValidate, work)
	e5 := h.Enter(work)
	assert.True(t, e5)
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(work))
	h.Exit(work)

	assert.False(t, h.IsBusy())
	assert.Equal(t, 0, h.NumWaiters())
}

func TestThreeDuplicate(t *testing.T) {
	h := NewQueueLock()
	assert.NotNil(t, h)
	assert.Equal(t, 0, h.NumWaiters())
	assert.False(t, h.IsBusy())

	e1 := h.Enter(myWorkUpdate)
	assert.True(t, e1)
	assert.Equal(t, 0, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	e2 := h.Enter(myWorkTest)
	assert.False(t, e2)
	assert.Equal(t, 1, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	e3 := h.Enter(myWorkValidate)
	assert.False(t, e3)
	assert.Equal(t, 2, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	// This will not add since myWorkTest is already waiting
	e := h.Enter(myWorkTest)
	assert.False(t, e)
	assert.Equal(t, 2, h.NumWaiters())
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(myWorkUpdate))

	h.Exit(myWorkUpdate)
	assert.Equal(t, 1, h.NumWaiters()) // One handed to channel
	assert.False(t, h.IsBusy())

	work, ok := tryChannel(h)
	assert.True(t, ok)
	assert.Equal(t, myWorkTest, work)
	e4 := h.Enter(work)
	assert.True(t, e4)
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(work))
	h.Exit(work)

	assert.False(t, h.IsBusy())
	assert.Equal(t, 0, h.NumWaiters()) // Last one sent to channel

	work, ok = tryChannel(h)
	assert.True(t, ok)
	assert.Equal(t, myWorkValidate, work)
	e5 := h.Enter(work)
	assert.True(t, e5)
	assert.True(t, h.IsBusy())
	assert.True(t, h.IsRunning(work))
	h.Exit(work)

	assert.False(t, h.IsBusy())
	assert.Equal(t, 0, h.NumWaiters())
}
