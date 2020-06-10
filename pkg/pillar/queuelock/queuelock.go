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

	log "github.com/sirupsen/logrus"
)

// Handle is the handle used by the caller
type Handle struct {
	sync.Mutex
	isRunning bool      // is something currently running?
	running   uint      // what is currently running holding the lock
	waiting   []uint    // things waiting to run
	next      chan uint // Tell user what to run next
}

// NewQueueLock creates a lock
func NewQueueLock() *Handle {
	log.Infof("NewQueueLock()")
	handle := Handle{next: make(chan uint, 1)}
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
		log.Infof("Enter(%d) queued", work)
		return false
	}
	hdl.isRunning = true
	hdl.running = work
	log.Infof("Enter(%d) ok", work)
	return true
}

// Exit ends the lock for this work and kicks the channel if there is
// waiting work. Caller must pass the same work as in the Enter call.
func (hdl *Handle) Exit(work uint) {
	hdl.Lock()
	defer hdl.Unlock()
	if !hdl.isRunning {
		log.Panicf("Exit but not running")
	}
	if hdl.running != work {
		log.Panicf("Exit mismatched running %d work %d",
			hdl.running, work)
	}
	hdl.isRunning = false
	hdl.running = 0
	if len(hdl.waiting) == 0 {
		log.Infof("Exit(%d) no waiting", work)
		return
	}
	log.Infof("Exit(%d) %d waiting", work, len(hdl.waiting))
	next := hdl.dequeue()
	select {
	case hdl.next <- next:
		log.Infof("Exit() sent %d", next)
	default:
		log.Panicf("Exit channel busy")
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
// Supress duplicates when adding
func (hdl *Handle) enqueue(work uint) {
	log.Infof("enqueue(%d) %d waiting", work, len(hdl.waiting))
	for i := range hdl.waiting {
		if hdl.waiting[i] == work {
			log.Infof("queue(%d) duplicate at %d, %d waiting",
				work, i, len(hdl.waiting))
			return
		}
	}
	hdl.waiting = append(hdl.waiting, work)
	log.Infof("queue(%d) done, %d waiting", work, len(hdl.waiting))
}

// Caller must hold lock
// Panic if empty
func (hdl *Handle) dequeue() uint {
	log.Infof("dequeue() %d waiting", len(hdl.waiting))
	if len(hdl.waiting) == 0 {
		log.Panicf("dequeue empty waiting")
	}
	work := hdl.waiting[0]
	hdl.waiting = hdl.waiting[1:]
	log.Infof("dequeue -> %d, %d waiting", work, len(hdl.waiting))
	return work
}
