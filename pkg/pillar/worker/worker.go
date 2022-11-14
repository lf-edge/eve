// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker is used to kick off some work to a goroutine and get a notification
// when the work is complete

package worker

import (
	"fmt"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

// Logger basic interface to send trace messages
type Logger interface {
	Tracef(format string, args ...interface{})
}

// Worker presenting the ability to interface with a single worker or pool of multiple
type Worker interface {
	NumPending() int
	NumResults() int
	MsgChan() <-chan Processor
	C() <-chan Processor
	Submit(work Work) error
	TrySubmit(work Work) (bool, error)
	Cancel(key string)
	Done()
	Pop(key string) *WorkResult
	Peek(key string) *WorkResult
}

// WorkFunction is the user's function to do the actual work
type WorkFunction func(ctx interface{}, work Work) WorkResult

// ResponseFunction is the user's function to process the response
type ResponseFunction func(ctx interface{}, res WorkResult) error

// Single an implementation of Worker that captures the worker channels
type Single struct {
	// Private
	requestChan chan<- Work
	resultChan  <-chan Processor
	sync.RWMutex
	requestCount uint // Number of work items submitted
	resultCount  uint // Number of work results processed
	workMap      map[string]bool
	resultMap    map[string]WorkResult
	handlers     map[string]Handler
	log          Logger
}

// Work is one work item
type Work struct {
	// Kind is the unique kind of work for the worker, e.g. install something or load something.
	// It is used to distinguish between different kinds of jobs. The specific handlers to use for the job
	// are determined by the Kind. In the future, jobs may be grouped into queues by Kind. Kind is required.
	Kind string
	// Key is a key for this job. It is unique across all jobs, and may be used to retrieve the WorkResult
	// later. Submitting two jobs with the same key results in the second one not being performed, as it already
	// exists. If Key is blank `""`, then two jobs with the same Key always will both be executed. However,
	// with a blank Key, there is no way to retrieve the result using Peek or Pop, and only can be retrieved
	// during the Process phase.
	Key string
	// Description arbitrary structure, used to pass arbitrary data to the handler function(s).
	Description interface{}
}

// WorkResult is output from doing Work
// The Key matches the key in the Work so that the user can match them
type WorkResult struct {
	Key         string
	Error       error
	ErrorTime   time.Time
	Output      string
	Description interface{}
}

// Private to ensure that callers use the Process function and count the
// number of pending
type privateResult struct {
	worker      *Single
	kind        string
	key         string
	error       error
	errorTime   time.Time
	output      string
	description interface{}
}

// Handler a tuple that describes what the type of request is, and what the request handler
// and response handler should be
type Handler struct {
	Request  WorkFunction
	Response ResponseFunction
}

// NewWorker creates a new function for a specific function and context
// function takes the context and the channels
func NewWorker(log Logger, ctx interface{}, length int, handlers map[string]Handler) Worker {
	requestChan := make(chan Work, length)
	resultChan := make(chan Processor, length)

	w := &Single{
		requestChan: requestChan,
		resultChan:  resultChan,
		workMap:     map[string]bool{},
		resultMap:   map[string]WorkResult{},
		handlers:    handlers,
		log:         log,
	}

	log.Tracef("Creating %s at %s", "w.processWork", agentlog.GetMyStack())
	go w.processWork(log, ctx, requestChan, resultChan)
	return w
}

// NumPending returns the number of pending work items
// Callers should use this to check if it is less than the length specified
// in NewWorker
func (w *Single) NumPending() int {
	w.RLock()
	defer w.RUnlock()
	return int(w.requestCount) - int(w.resultCount)
}

// NumResults returns the number of results waiting to be processed.
func (w *Single) NumResults() int {
	w.RLock()
	defer w.RUnlock()
	return len(w.resultMap)
}

// processWork calls the fn for each work until the requestChan is closed
func (w *Single) processWork(log Logger, ctx interface{}, requestChan <-chan Work, resultChan chan<- Processor) {

	log.Tracef("processWork starting for context %T", ctx)
	for work := range requestChan {
		var result WorkResult
		// find the correct handler for it
		if handler, ok := w.handlers[work.Kind]; ok {
			result = handler.Request(ctx, work)
		} else {
			result = WorkResult{
				Error:     fmt.Errorf("unknown work description type: %s", work.Kind),
				ErrorTime: time.Now(),
			}
		}

		priv := privateResult{
			kind:        work.Kind,
			key:         result.Key,
			error:       result.Error,
			errorTime:   result.ErrorTime,
			output:      result.Output,
			description: result.Description,
			worker:      w,
		}
		resultChan <- Processor{
			result: priv,
		}
		// no longer pending
		w.Lock()
		w.deletePendingLocked(work.Key)
		w.Unlock()
	}
	close(resultChan)
	log.Tracef("processWork done for context %T", ctx)
}

// MsgChan returns a channel to be used in a select loop.
// This is a duplicate of C
func (w *Single) MsgChan() <-chan Processor {
	return w.resultChan
}

// C returns a channel to be used in a select loop
func (w *Single) C() <-chan Processor {
	return w.resultChan
}

// Submit will pass work to the worker.
// Note that this will wait if the channel is busy hence
// the user has to pick an appropriate length of the channel for NewWorker
// Use worker.Pool to avoid such blocking.
// returns nil if the new job was submitted, JobInProgressError if a job with that
// key already ins progress, and other errors if it cannot proceed.
func (w *Single) Submit(work Work) error {
	_, err := w.submitImpl(work, true)
	return err
}

// TrySubmit will pass work to the worker if the channel/queue is not full.
// Returns true if work was submitted, otherwise false.
// returns JobInProgressError if a job with that key already ins progress
func (w *Single) TrySubmit(work Work) (bool, error) {
	return w.submitImpl(work, false)
}

func (w *Single) submitImpl(work Work, wait bool) (bool, error) {
	done := false
	// if this Key already exists and is being processed, do nothing
	w.RLock()
	if work.Key != "" && w.lookupPendingLocked(work.Key) {
		w.RUnlock()
		return done, &JobInProgressError{s: work.Key}
	}
	// Kind must be set to be handleable
	if work.Kind == "" {
		w.RUnlock()
		return done, fmt.Errorf("cannot process a job with a blank Kind")
	}
	if _, ok := w.handlers[work.Kind]; !ok {
		w.RUnlock()
		return done, fmt.Errorf("no registered handlers for a job of Kind '%s'",
			work.Kind)
	}
	w.RUnlock()
	if wait {
		w.requestChan <- work
		done = true
	} else {
		select {
		case w.requestChan <- work:
			done = true
		default:
			// Do nothing
		}
	}
	if done {
		w.Lock()
		w.requestCount++
		if work.Key != "" {
			w.addPendingLocked(work.Key)
		}
		w.Unlock()
	}
	return done, nil
}

// Cancel cancels a pending job.
// It is idempotent, will return no errors if the job is not found,
// which means it either never was submitted, or it already was processed.
func (w *Single) Cancel(key string) {
	w.Lock()
	defer w.Unlock()
	w.deletePendingLocked(key)
}

// Done will stop the worker
func (w *Single) Done() {
	close(w.requestChan)
}

// Pop get a result and remove it from the list
func (w *Single) Pop(key string) *WorkResult {
	if key == "" {
		return nil
	}
	// need to lookup up and delete under lock
	w.Lock()
	defer w.Unlock()
	res := w.lookupResultLocked(key)
	if res != nil {
		w.deleteResultLocked(key)
	}
	return res
}

// Peek get a result without removing it from the list
func (w *Single) Peek(key string) *WorkResult {
	if key == "" {
		return nil
	}
	w.RLock()
	defer w.RUnlock()
	return w.lookupResultLocked(key)
}

// lookupPendingLocked assumes caller holds lock
func (w *Single) lookupPendingLocked(key string) bool {
	res, ok := w.workMap[key]
	return ok && res
}

// addPendingLocked assumes caller holds lock
func (w *Single) addPendingLocked(key string) {
	w.workMap[key] = true
}

// deletePendingLocked assumes caller holds lock
func (w *Single) deletePendingLocked(key string) {
	delete(w.workMap, key)
}

// lookupResultLocked assumes caller holds lock
func (w *Single) lookupResultLocked(key string) *WorkResult {
	if res, ok := w.resultMap[key]; ok {
		return &res
	}
	return nil
}

// addResultLocked assumes caller holds lock
func (w *Single) addResultLocked(key string, res WorkResult) {
	w.resultMap[key] = res
}

// deleteResultLocked assumes caller holds lock
func (w *Single) deleteResultLocked(key string) {
	delete(w.resultMap, key)
}

// Processor struct that can process results
type Processor struct {
	result privateResult
}

// Process takes the output from the channel and returns the WorkResult.
// Can pass it an arbitrary context that will be passed to the handler,
// as well as whether to make it available for lookup afterwards via Pop/Peek.
// If false, it is here and that is it. If true, it will be available for Pop/Peek.
func (p Processor) Process(ctx interface{}, later bool) (err error) {
	kind := p.result.kind
	w := p.result.worker
	res := WorkResult{
		Key:         p.result.key,
		Error:       p.result.error,
		ErrorTime:   p.result.errorTime,
		Output:      p.result.output,
		Description: p.result.description,
	}
	w.Lock()
	w.resultCount++
	if later {
		w.addResultLocked(p.result.key, res)
	}
	w.Unlock()
	// find the correct handler for it
	if handler, ok := w.handlers[kind]; ok {
		if handler.Response == nil {
			return nil
		}
		return handler.Response(ctx, res)
	}
	return fmt.Errorf("unknown work description type %s", kind)
}
