// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker is used to kick off some work to a goroutine and get a notification
// when the work is complete

package worker

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

// Logger basic interface to send debug messages
type Logger interface {
	Debugf(format string, args ...interface{})
}

// Worker captures the worker channels
type Worker struct {
	// Private
	requestChan  chan<- Work
	resultChan   <-chan Processor
	requestCount uint // Number of work items submitted
	resultCount  uint // Number of work results processed
	workMap      map[string]bool
	resultMap    map[string]WorkResult
	handlers     map[string]Handler
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
	worker      *Worker
	kind        string
	key         string
	error       error
	errorTime   time.Time
	output      string
	description interface{}
}

// WorkFunction is the user's function to do the actual work
type WorkFunction func(ctx interface{}, work Work) WorkResult

// ResponseFunction is the user's function to process the response
type ResponseFunction func(ctx interface{}, res WorkResult) error

// Handler a tuple that describes what the type of request is, and what the request handler
// and response handler should be
type Handler struct {
	Request  WorkFunction
	Response ResponseFunction
}

// NewWorker creates a new function for a specific function and context
// function takes the context and the channels
func NewWorker(log Logger, ctx interface{}, length int, handlers map[string]Handler) *Worker {
	requestChan := make(chan Work, length)
	resultChan := make(chan Processor, length)

	w := &Worker{
		requestChan: requestChan,
		resultChan:  resultChan,
		workMap:     map[string]bool{},
		resultMap:   map[string]WorkResult{},
		handlers:    handlers,
	}

	log.Debugf("Creating %s at %s", "w.processWork", agentlog.GetMyStack())
	go w.processWork(log, ctx, requestChan, resultChan)
	return w
}

// NumPending returns the number of pending work items
// Callers should use this to check if it is less than the length specified
// in NewWorker
func (w Worker) NumPending() int {
	return int(w.requestCount) - int(w.resultCount)
}

// processWork calls the fn for each work until the requestChan is closed
func (w *Worker) processWork(log Logger, ctx interface{}, requestChan <-chan Work, resultChan chan<- Processor) {

	log.Debugf("processWork starting for context %T", ctx)
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
		w.deletePending(work.Key)
	}
	// XXX if we ever want multiple goroutines for one Worker we
	// can't close here; would need some wait for all to finish
	close(resultChan)
	log.Debugf("processWork done for context %T", ctx)
}

// MsgChan returns a channel to be used in a select loop.
// This is a duplicate of C
func (w *Worker) MsgChan() <-chan Processor {
	return w.resultChan
}

// C returns a channel to be used in a select loop
func (w *Worker) C() <-chan Processor {
	return w.resultChan
}

// Submit will pass work to the worker.
// Note that this will wait if channel is busy, hence
// user has to pick an appropriate length of the channel and use.
// returns nil if the new job was submitted, JobInProgressError if a job with that
// key already ins progress, and other errors if it cannot proceed.
func (w *Worker) Submit(work Work) error {
	// if this Key already exists and is being processed, do nothing
	if work.Key != "" && w.lookupPending(work.Key) {
		return &JobInProgressError{s: work.Key}
	}
	// Kind must be set to be handleable
	if work.Kind == "" {
		return fmt.Errorf("cannot process a job with a blank Kind")
	}
	if _, ok := w.handlers[work.Kind]; !ok {
		return fmt.Errorf("no registered handlers for a job of Kind '%s'", work.Kind)
	}
	w.requestChan <- work
	w.requestCount++
	if work.Key != "" {
		w.addPending(work.Key)
	}
	return nil
}

// Cancel cancels a pending job.
// It is idempotent, will return no errors if the job is not found,
// which means it either never was submitted, or it already was processed.
func (w *Worker) Cancel(key string) {
	w.deletePending(key)
}

// Done will stop the worker
func (w *Worker) Done() {
	close(w.requestChan)
}

// Pop get a result and remove it from the list
func (w *Worker) Pop(key string) *WorkResult {
	res := w.Peek(key)
	if w != nil {
		w.deleteResult(key)
	}
	return res
}

// Peek get a result without removing it from the list
func (w *Worker) Peek(key string) *WorkResult {
	if key == "" {
		return nil
	}
	return w.lookupResult(key)
}

func (w *Worker) lookupPending(key string) bool {
	res, ok := w.workMap[key]
	return ok && res
}

func (w *Worker) addPending(key string) {
	w.workMap[key] = true
}

func (w *Worker) deletePending(key string) {
	delete(w.workMap, key)
}

func (w *Worker) lookupResult(key string) *WorkResult {
	if res, ok := w.resultMap[key]; ok {
		return &res
	}
	return nil
}

func (w *Worker) addResult(key string, res WorkResult) {
	w.resultMap[key] = res
}

func (w *Worker) deleteResult(key string) {
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
	w.resultCount++
	if later {
		w.addResult(p.result.key, res)
	}
	// find the correct handler for it
	if handler, ok := w.handlers[kind]; ok {
		if handler.Response == nil {
			return nil
		}
		return handler.Response(ctx, res)
	}
	return fmt.Errorf("unknown work description type %s", kind)
}
