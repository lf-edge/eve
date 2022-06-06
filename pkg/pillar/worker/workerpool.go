// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker provides a dynamic set of workers so that work can be
// spawned without head-of-line blocking

package worker

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

const (
	defaultPeriodicGCSeconds = 300
	defaultSubmitGCSeconds   = 60
)

// Pool captures the workers in the pool
type Pool struct {
	// Private
	maxWorkers     int
	maxWorkersUsed int
	periodicGCTime time.Duration
	submitGCTime   time.Duration
	workers        []myworker
	workersLock    sync.RWMutex
	numChan        int32 // Number of result channels from workers
	resultChan     chan Processor
	log            Logger
	ctx            interface{}
	handlers       map[string]Handler
	stopTimer      chan struct{}
}

type myworker struct {
	worker   Worker
	lastUsed time.Time // Last successful submit
}

// NewPool constructs a pool
// If maxWorkers is set to zero it means unlimited
func NewPool(log Logger, ctx interface{}, maxWorkers int, handlers map[string]Handler) Worker {
	return NewPoolWithGC(log, ctx, maxWorkers, handlers,
		defaultPeriodicGCSeconds, defaultSubmitGCSeconds)
}

// NewPoolWithGC constructs a pool with non-default GC timers
// If maxWorkers is set to zero it means unlimited
func NewPoolWithGC(log Logger, ctx interface{}, maxWorkers int, handlers map[string]Handler, periodicGCSeconds int, submitGCSeconds int) Worker {
	length := maxWorkers
	if length == 0 {
		length = 10
	}
	resultChan := make(chan Processor, length)
	wp := &Pool{
		resultChan:     resultChan,
		maxWorkers:     maxWorkers,
		maxWorkersUsed: 1,
		log:            log,
		ctx:            ctx,
		handlers:       handlers,
		stopTimer:      make(chan struct{}),
		periodicGCTime: time.Duration(periodicGCSeconds) * time.Second,
		submitGCTime:   time.Duration(submitGCSeconds) * time.Second,
	}
	go wp.periodicGC()
	return wp
}

func (wp *Pool) periodicGC() {
	wp.log.Tracef("periodicGC starting")
	t := time.NewTicker(wp.periodicGCTime)
	done := false
	for !done {
		select {
		case <-t.C:
			wp.workersLock.Lock()
			wp.purgeOld(0)
			wp.workersLock.Unlock()

		case _, ok := <-wp.stopTimer:
			if !ok {
				done = true
			}
		}
	}
	wp.log.Tracef("periodicGC done")
}

func (wp *Pool) mergeResult(w Worker) {
	wp.log.Tracef("mergeResult starting")
	ch := w.MsgChan()
	for res := range ch {
		wp.log.Tracef("mergeResult got %+v", res)
		wp.resultChan <- res
	}
	// Are all the mergeResults done?
	if atomic.AddInt32(&wp.numChan, -1) == 0 {
		close(wp.resultChan)
	}
	wp.log.Tracef("mergeResult done")
}

// NumPending returns the current number work items
func (wp *Pool) NumPending() int {
	wp.workersLock.RLock()
	defer wp.workersLock.RUnlock()
	total := 0
	for _, w := range wp.workers {
		total += w.worker.NumPending()
	}
	return total
}

// NumResults returns the number of results waiting to be processed.
func (wp *Pool) NumResults() int {
	wp.workersLock.RLock()
	defer wp.workersLock.RUnlock()
	total := 0
	for _, w := range wp.workers {
		total += w.worker.NumResults()
	}
	return total
}

// NumWorkers returns the current number of workers
func (wp *Pool) NumWorkers() int {
	wp.workersLock.RLock()
	defer wp.workersLock.RUnlock()
	return len(wp.workers)
}

// Submit submits jobs to the WorkerPool. If it cannot find a worker in the pool
// that can service it - i.e. both the number of workers is at the maximum and the
// queues of all workers are full - then it waits one second and tries all available
// workers again, in an infinite loop until it finds an available worker.
// Returns nil if the new job was submitted, JobInProgressError if a job with that
// key already ins progress, and other errors if it cannot proceed.
func (wp *Pool) Submit(work Work) error {
	for {
		submitted, err := wp.TrySubmit(work)
		if err != nil {
			return err
		}
		// simple success case
		if submitted {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
}

// TrySubmit submits jobs to the WorkerPool. If it cannot find a worker in the pool
// that can service it - i.e. both the number of workers is at the maximum and the
// queues of all workers are full - returns false.
// returns JobInProgressError if a job with that key already in progress.
func (wp *Pool) TrySubmit(work Work) (bool, error) {
	wp.workersLock.Lock()
	defer wp.workersLock.Unlock()
	for i, w := range wp.workers {
		done, err := w.worker.TrySubmit(work)
		if err != nil {
			wp.log.Tracef("failed TrySubmit for %d", i)
			return done, err
		} else if done {
			wp.log.Tracef("succeeded TrySubmit for %d", i)
			w.lastUsed = time.Now()
			wp.purgeOld(i + 1)
			return done, nil
		}
	}
	// Used all of them; can we create a new one?
	if wp.maxWorkers == 0 || len(wp.workers) < wp.maxWorkers {
		wp.log.Tracef("Creating new worker")
		w := NewWorker(wp.log, wp.ctx, 0, wp.handlers)
		neww := myworker{worker: w, lastUsed: time.Now()}
		wp.workers = append(wp.workers, neww)
		if len(wp.workers) > wp.maxWorkersUsed {
			wp.maxWorkersUsed = len(wp.workers)
			wp.log.Tracef("maxWorkersUsed %d", wp.maxWorkersUsed)
		}
		atomic.AddInt32(&wp.numChan, 1)
		wp.log.Tracef("Creating %s at %s", "wp.mergeResult",
			agentlog.GetMyStack())
		go wp.mergeResult(w)
		err := w.Submit(work)
		if err != nil {
			wp.log.Tracef("new worker yet failed: %s", err)
			return false, err
		}
		wp.log.Tracef("succeeded Submit for %d", len(wp.workers))
		return true, nil
	}
	wp.log.Tracef("Would exceed maxWorkers of %d", wp.maxWorkers)
	return false, fmt.Errorf("Would exceed maxWorkers of %d", wp.maxWorkers)
}

// MsgChan returns a channel to be used in a select loop.
// This is a duplicate of C
func (wp *Pool) MsgChan() <-chan Processor {
	return wp.resultChan
}

// C returns a channel to be used in a select loop.
// This is a duplicate of MsgChan
func (wp *Pool) C() <-chan Processor {
	return wp.resultChan
}

// Cancel cancels a pending job.
// It is idempotent, will return no errors if the job is not found,
// which means it either never was submitted, or it already was processed.
func (wp *Pool) Cancel(key string) {
	wp.workersLock.RLock()
	defer wp.workersLock.RUnlock()
	for _, w := range wp.workers {
		w.worker.Cancel(key)
	}
}

// Done will stop the workers
func (wp *Pool) Done() {
	wp.workersLock.Lock()
	defer wp.workersLock.Unlock()
	for _, w := range wp.workers {
		w.worker.Done()
	}
	wp.workers = nil
	close(wp.stopTimer)
}

// Pop get a result and remove it from the list
func (wp *Pool) Pop(key string) *WorkResult {
	wp.workersLock.RLock()
	defer wp.workersLock.RUnlock()
	for _, w := range wp.workers {
		res := w.worker.Pop(key)
		if res != nil {
			return res
		}
	}
	return nil
}

// Peek get a result without removing it from the list
func (wp *Pool) Peek(key string) *WorkResult {
	wp.workersLock.RLock()
	defer wp.workersLock.RUnlock()
	for _, w := range wp.workers {
		res := w.worker.Peek(key)
		if res != nil {
			return res
		}
	}
	return nil
}

// purgeOld removes old workers from the pool
// expect workersLock acquired
func (wp *Pool) purgeOld(startIndex int) {

	wp.log.Tracef("purgeOld(%d) have %d", startIndex, len(wp.workers))
	var newWorkers []myworker
	for i, w := range wp.workers {
		if i <= startIndex || time.Since(w.lastUsed) < wp.submitGCTime ||
			w.worker.NumPending() != 0 || w.worker.NumResults() != 0 {

			newWorkers = append(newWorkers, w)
		} else {
			wp.log.Tracef("purgeOld GC %d", i)
			w.worker.Done()
		}
	}
	wp.workers = newWorkers
	wp.log.Tracef("purgeOld post GC have %d", len(wp.workers))
}
