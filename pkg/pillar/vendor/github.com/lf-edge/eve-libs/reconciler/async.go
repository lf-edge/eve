// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"sync"
	"time"

	dg "github.com/lf-edge/eve-libs/depgraph"
)

const (
	// If asynchronous operation does not react to cancel within 1 minute,
	// reconciler will consider it as failed.
	cancelTimeout = time.Minute
)

// graphCtx is stored as PrivateData of the graph with the current state
// (at its root).
type graphCtx struct {
	asyncManager *asyncManager
}

// asyncManager is used to manage operations running asynchronously.
type asyncManager struct {
	sync.Mutex
	// List of asynchronous operations still running or not fully processed
	// by the reconciler.
	asyncOps map[uint64]*asyncOpCtx
	// resume channel
	resumeChan chan string
	// List of graphs for which Resume signal has been already fired since
	// the last Reconcile
	firedResumeFor []string
	// Wait group for all asynchronous operations still running.
	wg sync.WaitGroup
}

func newGraphCtx() *graphCtx {
	return &graphCtx{
		asyncManager: &asyncManager{
			asyncOps:   make(map[uint64]*asyncOpCtx),
			resumeChan: make(chan string, 32),
		},
	}
}

func (c *asyncManager) reconcileStarts() {
	c.Lock()
	defer c.Unlock()
	c.firedResumeFor = []string{}
}

func (c *asyncManager) reconcileEnds() (anyAsyncOps bool, resumeChan <-chan string) {
	c.Lock()
	defer c.Unlock()
	if len(c.asyncOps) > 0 {
		return true, c.resumeChan
	}
	return false, nil
}

func (c *asyncManager) cancelOps(cancelForItem func(ref dg.ItemRef) bool) {
	c.Lock()
	defer c.Unlock()
	for _, asyncOp := range c.asyncOps {
		if cancelForItem != nil && !cancelForItem(asyncOp.params.itemRef) {
			continue
		}
		if cancel := asyncOp.params.cancel; cancel != nil {
			cancel()
			asyncOp.status.cancelTime = time.Now()
		}
	}
}

// Note: opIsDone can be called even before addAsyncOp()!
func (c *asyncManager) opIsDone(opID uint64, graphName string, err error) {
	c.Lock()
	defer c.Unlock()
	if _, exists := c.asyncOps[opID]; !exists {
		c.asyncOps[opID] = &asyncOpCtx{
			params: asyncOpParams{
				opID:      opID,
				graphName: graphName,
				startTime: time.Now(),
			},
			status: asyncOpStatus{
				done:    true,
				endTime: time.Now(),
				err:     err,
			},
		}
	} else {
		c.asyncOps[opID].status = asyncOpStatus{
			done:    true,
			endTime: time.Now(),
			err:     err,
		}
		c.wg.Done()
	}
	var signalFired bool
	for _, firedFor := range c.firedResumeFor {
		if firedFor == graphName {
			signalFired = true
		}
	}
	if !signalFired {
		select {
		case c.resumeChan <- graphName:
			// Signal to resume was sent.
			c.firedResumeFor = append(c.firedResumeFor, graphName)
		default:
			// Channel is full, ignore.
			// Notification for this graph is probably already waiting in the channel.
		}
	}
}

func (c *asyncManager) getAsyncOp(opID uint64) (status asyncOpCtx, found bool) {
	c.Lock()
	defer c.Unlock()
	asyncOp, found := c.asyncOps[opID]
	if found {
		return *asyncOp, true
	}
	return asyncOpCtx{}, false
}

func (c *asyncManager) listAllOps() (list []asyncOpCtx) {
	c.Lock()
	defer c.Unlock()
	for _, asyncOp := range c.asyncOps {
		list = append(list, *asyncOp)
	}
	return list
}

func (c *asyncManager) delAsyncOp(opID uint64) bool {
	c.Lock()
	defer c.Unlock()
	if asyncOp, found := c.asyncOps[opID]; found {
		if !asyncOp.status.done {
			// reconciler does not care about this operation anymore
			// (cancel timeout has run out)
			c.wg.Done()
		}
		delete(c.asyncOps, opID)
	}
	return false
}

// Note: opIsDone can be called even before addAsyncOp()!
func (c *asyncManager) addAsyncOp(params asyncOpParams) {
	c.Lock()
	defer c.Unlock()
	if _, exists := c.asyncOps[params.opID]; exists {
		c.asyncOps[params.opID].params = params
		return
	}
	c.asyncOps[params.opID] = &asyncOpCtx{params: params}
	c.wg.Add(1)
}

func (c *asyncManager) waitForOps() {
	c.wg.Wait()
}

// opCtx is passed from Reconciler to Create/Modify/Delete.
type opCtx struct {
	// Randomly generated operation ID.
	opID uint64
	// Name of the graph which is being reconciled.
	graphName string
	// Used to call opIsDone().
	asyncManager *asyncManager
	// For Create/Modify/Delete to inform the Reconciler that the operation
	// will run asynchronously.
	runAsync bool
}

type asyncOpCtx struct {
	params asyncOpParams
	status asyncOpStatus
}

type asyncOpParams struct {
	// Randomly generated operation ID.
	opID uint64
	// Time when the operation started.
	startTime time.Time
	// Item for which the operation runs.
	itemRef dg.ItemRef
	// Name of graph the reconciliation of which triggered the operation.
	graphName string
	// Cancel callback associated with the context passed to the operation.
	cancel func()
}

type asyncOpStatus struct {
	// If true, the asynchronous operation has already finalized.
	done bool
	// Time when the asynchronous operation finalized.
	endTime time.Time
	// Time when the operation was canceled with cancel().
	// Even if operation has been already canceled, ".done" may still be false
	// if the operation has not yet reacted to cancel.
	cancelTime time.Time
	// Error value returned by an asynchronous operation.
	err error
}

// Returns true if the async operation failed to react to a cancel in time.
func (s asyncOpStatus) cancelTimeout() bool {
	endTime := s.endTime
	if !s.done {
		endTime = time.Now()
	}
	return !s.cancelTime.IsZero() && endTime.Sub(s.cancelTime) > cancelTimeout
}
