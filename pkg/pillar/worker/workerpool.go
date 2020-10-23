// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker provides a dynamic set of workers so that work can be
// spawned without head-of-line blocking

package worker

import (
	"fmt"
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
	numChan        int // Number of result channels from workers
	resultChan     chan Processor
	log            Logger
	ctx            interface{}
	handlers       map[string]Handler
	stopTimer      chan struct{}
}

type myworker struct {
	worker   *Worker
	lastUsed time.Time // Last successful submit
}

// NewPool constructs a pool
// If maxWorkers is set to zero it means unlimited
func NewPool(log Logger, ctx interface{}, maxWorkers int, handlers map[string]Handler) *Pool {
	return NewPoolWithGC(log, ctx, maxWorkers, handlers,
		defaultPeriodicGCSeconds, defaultSubmitGCSeconds)
}

// NewPoolWithGC constructs a pool with non-default GC timers
// If maxWorkers is set to zero it means unlimited
func NewPoolWithGC(log Logger, ctx interface{}, maxWorkers int, handlers map[string]Handler, periodicGCSeconds int, submitGCSeconds int) *Pool {
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
	wp.log.Debugf("periodicGC starting")
	t := time.NewTicker(wp.periodicGCTime)
	done := false
	for !done {
		select {
		case <-t.C:
			wp.purgeOld(0)

		case _, ok := <-wp.stopTimer:
			if !ok {
				done = true
			}
		}
	}
	wp.log.Debugf("periodicGC done")
}

func (wp *Pool) mergeResult(w *Worker) {
	wp.log.Debugf("mergeResult starting")
	ch := w.MsgChan()
	for res := range ch {
		wp.log.Debugf("mergeResult got %+v", res)
		wp.resultChan <- res
	}
	wp.numChan--
	// Are all the mergeResults done?
	if wp.numChan == 0 {
		close(wp.resultChan)
	}
	wp.log.Debugf("mergeResult done")
}

// NumPending returns the current number work items
func (wp *Pool) NumPending() int {
	total := 0
	for _, w := range wp.workers {
		total += w.worker.NumPending()
	}
	return total
}

// NumWorkers returns the current number of workers
func (wp *Pool) NumWorkers() int {
	return len(wp.workers)
}

// TrySubmit returns false if the number of workers is already at the max
// returns JobInProgressError if a job with that key already in progress
func (wp *Pool) TrySubmit(work Work) (bool, error) {
	for i, w := range wp.workers {
		done, err := w.worker.TrySubmit(work)
		if err != nil {
			wp.log.Debugf("failed TrySubmit for %d", i)
			return done, err
		} else if done {
			wp.log.Debugf("succeeded TrySubmit for %d", i)
			w.lastUsed = time.Now()
			wp.purgeOld(i + 1)
			return done, nil
		}
	}
	// Used all of them; can we create a new one?
	if wp.maxWorkers == 0 || len(wp.workers) < wp.maxWorkers {
		wp.log.Debugf("Creating new worker")
		w := NewWorker(wp.log, wp.ctx, 0, wp.handlers)
		neww := myworker{worker: w, lastUsed: time.Now()}
		wp.workers = append(wp.workers, neww)
		if len(wp.workers) > wp.maxWorkersUsed {
			wp.maxWorkersUsed = len(wp.workers)
			wp.log.Debugf("maxWorkersUsed %d", wp.maxWorkersUsed)
		}
		wp.numChan++
		wp.log.Debugf("Creating %s at %s", "wp.mergeResult",
			agentlog.GetMyStack())
		go wp.mergeResult(w)
		err := w.Submit(work)
		if err != nil {
			wp.log.Debugf("new worker yet failed: %s", err)
			return false, err
		}
		wp.log.Debugf("succeeded Submit for %d", len(wp.workers))
		return true, nil
	}
	wp.log.Debugf("Would exceed maxWorkers of %d", wp.maxWorkers)
	return false, fmt.Errorf("Would exceed maxWorkers of %d", wp.maxWorkers)
}

// MsgChan returns a channel to be used in a select loop.
// This is a duplicate of C
func (wp *Pool) MsgChan() <-chan Processor {
	return wp.resultChan
}

// Cancel cancels a pending job.
// It is idempotent, will return no errors if the job is not found,
// which means it either never was submitted, or it already was processed.
func (wp *Pool) Cancel(key string) {
	for _, w := range wp.workers {
		w.worker.Cancel(key)
	}
}

// Done will stop the workers
func (wp *Pool) Done() {
	for _, w := range wp.workers {
		w.worker.Done()
	}
	wp.workers = nil
	close(wp.stopTimer)
}

// Pop get a result and remove it from the list
func (wp *Pool) Pop(key string) *WorkResult {
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
	for _, w := range wp.workers {
		res := w.worker.Peek(key)
		if res != nil {
			return res
		}
	}
	return nil
}

// purgeOld removes old workers from the pool
func (wp *Pool) purgeOld(startIndex int) {

	wp.log.Debugf("purgeOld(%d) have %d", startIndex, len(wp.workers))
	var newWorkers []myworker
	for i, w := range wp.workers {
		if i <= startIndex || time.Since(w.lastUsed) < wp.submitGCTime {
			newWorkers = append(newWorkers, w)
		} else {
			wp.log.Debugf("purgeOld GC %d", i)
			w.worker.Done()
		}
	}
	wp.workers = newWorkers
	wp.log.Debugf("purgeOld post GC have %d", len(wp.workers))
}
