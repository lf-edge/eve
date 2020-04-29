// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker is used to kick off some work to a goroutine and get a notification
// when the work is complete

package worker

import (
	"time"

	log "github.com/sirupsen/logrus"
)

// Worker captures the worker channels
type Worker struct {
	// Private
	requestChan  chan<- Work
	resultChan   <-chan privateResult
	requestCount uint // Number of work items submitted
	resultCount  uint // Number of work results processed
}

// Work is one work item
// Key is used to match with the WorkResult
// The description is specific for the particular worker function
type Work struct {
	Key         string
	Description interface{}
}

// WorkResult is output from doing Work
// The Key matches the key in the Work so that the user can match them
type WorkResult struct {
	Key       string
	Error     error
	ErrorTime time.Time
	Output    string
}

// Private to ensure that callers use the Process function and count the
// number of pending
type privateResult struct {
	key       string
	error     error
	errorTime time.Time
	output    string
}

// WorkFunction is the user's function to do the actual work
type WorkFunction func(ctx interface{}, work Work) WorkResult

// NewWorker creates a new function for a specific function and context
// function takes the context and the channels
func NewWorker(fn WorkFunction, ctx interface{}, length int) *Worker {
	w := new(Worker)
	requestChan := make(chan Work, length)
	resultChan := make(chan privateResult, length)
	go w.processWork(ctx, fn, requestChan, resultChan)
	w.requestChan = requestChan
	w.resultChan = resultChan
	return w
}

// NumPending returns the number of pending work items
// Callers should use this to check if it is less than the length specified
// in NewWorker
func (workerPtr Worker) NumPending() int {
	return int(workerPtr.requestCount) - int(workerPtr.resultCount)
}

// processWork calls the fn for each work until the requestChan is closed
func (workerPtr *Worker) processWork(ctx interface{}, fn WorkFunction, requestChan <-chan Work, resultChan chan<- privateResult) {

	log.Infof("processWork starting for context %T", ctx)
	for w := range requestChan {
		result := fn(ctx, w)
		priv := privateResult{
			key:       result.Key,
			error:     result.Error,
			errorTime: result.ErrorTime,
			output:    result.Output,
		}
		resultChan <- priv
	}
	// XXX if we ever want multiple goroutines for one Worker we
	// can't close here; would need some wait for all to finish
	close(resultChan)
	log.Infof("processWork done for context %T", ctx)
}

// MsgChan returns a channel to be used in a select loop
func (workerPtr *Worker) MsgChan() <-chan privateResult { //revive:disable
	return workerPtr.resultChan
}

// Process takes the output from the channel and returns the WorkResult
func (workerPtr *Worker) Process(priv privateResult) WorkResult {
	workerPtr.resultCount++
	result := WorkResult{
		Key:       priv.key,
		Error:     priv.error,
		ErrorTime: priv.errorTime,
		Output:    priv.output,
	}
	return result
}

// Submit will pass work to the worker
// Note that this will wait if channel is busy hence
// user has to pick an appropriate length of the channel and use
func (workerPtr *Worker) Submit(w Work) {
	workerPtr.requestChan <- w
	workerPtr.requestCount++
}

// Done will stop the worker
func (workerPtr *Worker) Done() {
	close(workerPtr.requestChan)
}
