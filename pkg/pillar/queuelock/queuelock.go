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
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// Handle is the handle used by the caller
type Handle struct {
	sync.Mutex
	isRunning bool      // is something currently running?
	running   uint      // what is currently running holding the lock
	waiting   []uint    // things waiting to run
	next      chan uint // Tell user what to run next
	log       *base.LogObject
}

// NewQueueLock creates a lock
func NewQueueLock(log *base.LogObject) *Handle {
	log.Functionf("NewQueueLock()")
	handle := Handle{
		next: make(chan uint, 1),
		log:  log,
	}
	return &handle
}

// MsgChan returns the channel
func (hdl *Handle) MsgChan() <-chan uint {
	return hdl.next
}

// Enter returns true if successful i.e., nothing was already running
// Otherwise the caller is expected to select on MsgChan to get notified
// when it can try again.
func (hdl *Handle) Enter(work uint) bool {
	hdl.Lock()
	defer hdl.Unlock()
	if hdl.isRunning {
		hdl.enqueue(work)
		hdl.log.Functionf("Enter(%d) queued", work)
		return false
	}
	hdl.isRunning = true
	hdl.running = work
	hdl.log.Functionf("Enter(%d) ok", work)
	return true
}

// Exit ends the lock for this work and kicks the channel if there is
// waiting work. Caller must pass the same work as in the Enter call.
func (hdl *Handle) Exit(work uint) {
	hdl.Lock()
	defer hdl.Unlock()
	if !hdl.isRunning {
		hdl.log.Panicf("Exit but not running")
	}
	if hdl.running != work {
		hdl.log.Panicf("Exit mismatched running %d work %d",
			hdl.running, work)
	}
	hdl.isRunning = false
	hdl.running = 0
	if len(hdl.waiting) == 0 {
		hdl.log.Functionf("Exit(%d) no waiting", work)
		return
	}
	hdl.log.Functionf("Exit(%d) %d waiting", work, len(hdl.waiting))
	next := hdl.dequeue()
	select {
	case hdl.next <- next:
		hdl.log.Functionf("Exit() sent %d", next)
	default:
		hdl.log.Panicf("Exit channel busy")
	}
}

// IsBusy returns whether the queuelock is held by anybody
func (hdl *Handle) IsBusy() bool {
	return hdl.isRunning
}

// IsRunning returns whether the queuelock is held by work
func (hdl *Handle) IsRunning(work uint) bool {
	return hdl.IsBusy() && hdl.running == work
}

// NumWaiters returns the number of work items waiting
func (hdl *Handle) NumWaiters() int {
	hdl.Lock()
	defer hdl.Unlock()
	return len(hdl.waiting)
}

// Caller must hold lock
// Suppress duplicates when adding
func (hdl *Handle) enqueue(work uint) {
	hdl.log.Functionf("enqueue(%d) %d waiting", work, len(hdl.waiting))
	for i := range hdl.waiting {
		if hdl.waiting[i] == work {
			hdl.log.Functionf("queue(%d) duplicate at %d, %d waiting",
				work, i, len(hdl.waiting))
			return
		}
	}
	hdl.waiting = append(hdl.waiting, work)
	hdl.log.Functionf("queue(%d) done, %d waiting", work, len(hdl.waiting))
}

// Caller must hold lock
// Panic if empty
func (hdl *Handle) dequeue() uint {
	hdl.log.Functionf("dequeue() %d waiting", len(hdl.waiting))
	if len(hdl.waiting) == 0 {
		hdl.log.Panicf("dequeue empty waiting")
	}
	work := hdl.waiting[0]
	hdl.waiting = hdl.waiting[1:]
	hdl.log.Functionf("dequeue -> %d, %d waiting", work, len(hdl.waiting))
	return work
}
