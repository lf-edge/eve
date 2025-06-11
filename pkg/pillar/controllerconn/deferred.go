// Copyright (c) 2018-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Support for deferring sending of messages after a failure

package controllerconn

import (
	"bytes"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Example usage:
// queue := controllerconn.CreateDeferredQueue(ctrlClient, ...)
//
// In order to send created deferred item immediately:
//     queue.SetDeferred(key, buf, url, ...)
//
// If item was created with the `ignoreErr` flag set,
// then item will be removed from the queue regardless
// the actual send result.
//
// If `ignoreErr` is not set and an error occurs during
// the send, then queue processing is interrupted. The
// queue process will be repeated by the timer, see the
// `startTimer()` routine. `KickTimerNow` can be called
// in order to restart queue processing immediately.
//
// The deferred item can be removed from the queue if
// the send failed:
//     queue.RemoveDeferred(key)

type deferredItem struct {
	itemType interface{}
	key      string
	buf      *bytes.Buffer
	url      string
	opts     DeferredItemOpts
}

// DeferredItemOpts defines configurable options for processing a deferred item.
// These options control request behavior such as error handling, network tracing,
// logging, and retry policy across network interfaces.
type DeferredItemOpts struct {
	// Return 4xx and 5xx without trying other interfaces
	BailOnHTTPErr bool
	// WithNetTracing enables network tracing for post-mortem troubleshooting purposes.
	WithNetTracing bool
	// IgnoreErr, when set to true, allows the deferred queue to continue processing
	// subsequent items even if sending this item fails (e.g., due to network errors
	// or non-2xx HTTP responses). If false, a send failure will pause the queue
	// processing until retried later. All results, including failures, are still
	// reported to the sentHandler callback.
	IgnoreErr bool
	// SuppressLogs lowers the log severity to Trace for all Send-related methods,
	// suppressing higher-severity log output.
	SuppressLogs bool
	// Allow DNS server proxy listening on a loopback IP address.
	// This is currently used only for unit testing purposes to support host operating
	// systems with DNS proxy (such as systemd with systemd-resolved).
	AllowLoopbackDNS bool
}

// We create a timer with really a huge duration to avoid any problems
// with timer recreation, so we keep timer always alive.
const longTime1 = time.Hour * 24
const longTime2 = time.Hour * 48

// Used for exponential backoff when queue is active
const shortTime1 = time.Minute * 1
const shortTime2 = time.Minute * 15
const noise = shortTime1

// DeferredQueue is used so defer send requests and execute them later
// in the background.
type DeferredQueue struct {
	log                    *base.LogObject
	deferredItems          []*deferredItem
	deferredItemsLock      *sync.Mutex
	Ticker                 flextimer.FlexTickerHandle
	priorityCheckFunctions []TypePriorityCheckFunction
	sentHandler            SentHandlerFunction
	ctrlClient             *Client
	iteration              int
}

// TypePriorityCheckFunction returns true in case of find type with high priority
type TypePriorityCheckFunction func(itemType interface{}) bool

// SentHandlerFunction allow doing something with data if it was handled
// result indicates sending result
type SentHandlerFunction func(
	itemType interface{}, data *bytes.Buffer, result types.SenderStatus,
	traces []netdump.TracedNetRequest)

// CreateDeferredQueue creates and returns a deferred queue.
// We always keep a flextimer running so that we can return
// the associated channel. We adjust the times when we start and stop
// the timer.
// sentHandler is callback which will be run on successful sent
// priorityCheckFunctions may be added to send item with matched itemType firstly
// default function at the end of priorityCheckFunctions added to serve non-priority items
func CreateDeferredQueue(log *base.LogObject, ctrlClient *Client,
	ps *pubsub.PubSub, agentName string, ctxName string,
	warningTime time.Duration, errorTime time.Duration,
	sentHandler SentHandlerFunction,
	priorityCheckFunctions ...TypePriorityCheckFunction) *DeferredQueue {
	// Default "accept all" priority
	priorityCheckFunctions = append(priorityCheckFunctions,
		func(obj interface{}) bool {
			return true
		})

	queue := &DeferredQueue{
		log:                    log,
		deferredItemsLock:      &sync.Mutex{},
		Ticker:                 flextimer.NewRangeTicker(longTime1, longTime2),
		sentHandler:            sentHandler,
		priorityCheckFunctions: priorityCheckFunctions,
		ctrlClient:             ctrlClient,
	}

	// Start processing task
	go queue.processQueueTask(ps, agentName, ctxName,
		warningTime, errorTime)

	return queue
}

func (q *DeferredQueue) processQueueTask(ps *pubsub.PubSub,
	agentName string, ctxName string,
	warningTime time.Duration, errorTime time.Duration) {

	wdName := agentName + ctxName

	stillRunning := time.NewTicker(25 * time.Second)
	if ps != nil {
		ps.StillRunning(wdName, warningTime, errorTime)
		ps.RegisterFileWatchdog(wdName)
	}

	for {
		select {
		case <-q.Ticker.C:
			start := time.Now()
			if !q.handleDeferred() {
				q.log.Functionf("processQueueTask: some deferred items remain to be sent")
			}
			if ps != nil {
				ps.CheckMaxTimeTopic(agentName, ctxName, start, warningTime, errorTime)
			}
		case <-stillRunning.C:
		}
		if ps != nil {
			ps.StillRunning(wdName, warningTime, errorTime)
		}
	}
}

// mergeQueuesNoLock merges requests which were not sent (argument)
// with incoming requests, accumulated in the `ctx.deferredItems`.
// The caller must hold q.deferredItemsLock when invoking this method.
func (q *DeferredQueue) mergeQueuesNoLock(notSentReqs []*deferredItem) {
	if len(q.deferredItems) > 0 {
		// During the send new items land into the `ctx.deferredItems`
		// queue, which keys can exist in the `notSentReqs` queue.
		// Traverse requests which were not sent, find items with same
		// keys in the `ctx.deferredItems` and replace item in the
		// `notSentReqs`.
		for i, oldItem := range notSentReqs {
			for j, newItem := range q.deferredItems {
				if oldItem.key == newItem.key {
					// Replace item in head
					notSentReqs[i] = newItem
					// Remove from tail
					q.deferredItems =
						append(q.deferredItems[:j], q.deferredItems[j+1:]...)
					break
				}
			}
		}
	}
	// Merge the rest adding new items to the tail
	q.deferredItems = append(notSentReqs, q.deferredItems...)
}

// handleDeferred try to send all deferred items
func (q *DeferredQueue) handleDeferred() bool {
	q.deferredItemsLock.Lock()
	reqs := q.deferredItems
	q.deferredItems = []*deferredItem{}
	q.deferredItemsLock.Unlock()

	if len(reqs) == 0 {
		return true
	}

	q.log.Functionf("handleDeferred items %d", len(reqs))

	exit := false
	sent := 0
	ctx, cancel := q.ctrlClient.GetContextForAllIntfFunctions()
	defer cancel()
	for _, f := range q.priorityCheckFunctions {
		for _, item := range reqs {
			key := item.key
			//check with current priority function
			if !f(item.itemType) {
				continue
			}
			if item.buf == nil {
				continue
			}
			q.log.Functionf("handleDeferred: Trying to send for %s", key)
			if item.buf.Len() == 0 {
				q.log.Functionf("handleDeferred: Zero length deferred item for %s",
					key)
				continue
			}

			//SenderStatusNone indicates no problems
			rv, err := q.ctrlClient.SendOnAllIntf(ctx, item.url, item.buf,
				RequestOptions{
					SuppressLogs:     item.opts.SuppressLogs,
					WithNetTracing:   item.opts.WithNetTracing,
					BailOnHTTPErr:    item.opts.BailOnHTTPErr,
					Iteration:        q.iteration,
					AllowLoopbackDNS: item.opts.AllowLoopbackDNS,
				})
			// We check StatusCode before err since we do not want
			// to exit the loop just because some message is rejected
			// by the controller.
			if item.opts.BailOnHTTPErr && rv.HTTPResp != nil &&
				rv.HTTPResp.StatusCode >= 400 && rv.HTTPResp.StatusCode < 600 {
				q.log.Functionf("handleDeferred: for %s ignore code %d",
					key, rv.HTTPResp.StatusCode)
			} else if err != nil {
				q.log.Functionf("handleDeferred: for %s status %d failed %s",
					key, rv.Status, err)
				exit = !item.opts.IgnoreErr
				// Make sure we pass a non-zero result to the sentHandler.
				if rv.Status == types.SenderStatusNone {
					rv.Status = types.SenderStatusFailed
				}
			} else if rv.Status != types.SenderStatusNone {
				q.log.Functionf("handleDeferred: for %s received unexpected status %d",
					key, rv.Status)
				exit = !item.opts.IgnoreErr
			}
			if q.sentHandler != nil {
				q.sentHandler(item.itemType, item.buf, rv.Status, rv.TracedReqs)
			}

			//try with another interface next time
			q.iteration++

			if exit {
				break
			}
			item.buf = nil
			sent++
		}
		if exit {
			break
		}
	}

	var notSentReqs []*deferredItem
	if sent == 0 {
		// Take the whole queue
		notSentReqs = reqs
	} else {
		// Keep not sent requests
		for _, el := range reqs {
			if el.buf != nil {
				notSentReqs = append(notSentReqs, el)
			}
		}
	}

	if len(notSentReqs) > 0 {
		// Log the content of the rest in the queue
		q.log.Functionf("handleDeferred() the rest to be sent: %d",
			len(notSentReqs))
		if q.sentHandler != nil {
			for _, item := range notSentReqs {
				q.sentHandler(item.itemType, item.buf, types.SenderStatusDebug, nil)
			}
		}
	}

	q.deferredItemsLock.Lock()
	q.mergeQueuesNoLock(notSentReqs)
	if len(q.deferredItems) == 0 {
		q.stopTimer()
	}
	q.deferredItemsLock.Unlock()

	allSent := len(notSentReqs) == 0

	return allSent
}

// SetDeferred sets or replaces any item for the specified key and
// starts the timer. Key is used for identifying the channel. Please
// note that for deviceUUID key is used for attestUrl, which is not the
// same for other Urls, where in other case, the key is very specific
// for the object. If @opts.IgnoreErr is true the queue processing is not
// stopped on any error and will continue, although all errors will be
// passed to @sentHandler callback (see the CreateDeferredCtx()).
func (q *DeferredQueue) SetDeferred(
	key string, buf *bytes.Buffer, url string, itemType interface{},
	opts DeferredItemOpts) {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()

	var size int
	if buf != nil {
		size = buf.Len()
	}
	q.log.Functionf("SetDeferred(%s) size %d items %d",
		key, size, len(q.deferredItems))
	if len(q.deferredItems) == 0 {
		q.startTimer()
	}
	item := deferredItem{
		key:      key,
		itemType: itemType,
		buf:      buf,
		url:      url,
		opts:     opts,
	}
	found := false
	ind := 0
	var itemList *deferredItem
	for ind, itemList = range q.deferredItems {
		if itemList.key == key {
			found = true
			break
		}
	}
	if found {
		q.log.Tracef("Replacing key %s", key)
		q.deferredItems[ind] = &item
	} else {
		q.log.Tracef("Adding key %s", key)
		q.deferredItems = append(q.deferredItems, &item)
	}

	// Run to a completion from the processing task
	q.KickTimerNow()
}

// RemoveDeferred removes key from deferred items if exists
func (q *DeferredQueue) RemoveDeferred(key string) {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()

	q.log.Functionf("RemoveDeferred(%s) items %d",
		key, len(q.deferredItems))

	for ind, itemList := range q.deferredItems {
		if itemList.key == key {
			q.log.Tracef("Deleting key %s", key)
			q.deferredItems = append(q.deferredItems[:ind], q.deferredItems[ind+1:]...)
			break
		}
	}
	if len(q.deferredItems) == 0 {
		q.stopTimer()
	}
}

// KickTimerNow kicks the timer for immediate execution
func (q *DeferredQueue) KickTimerNow() {
	q.Ticker.TickNow()
}

// KickTimerWithinMinute kicks the timer for execution in random time
// within a minute (reasonable time) to avoid an avalanche of messages
// once connection being restored to the controller.
func (q *DeferredQueue) KickTimerWithinMinute() {
	// This re-configures the interval start for the ticker, keeping
	// the interval end and noise parameters same, which guarantees
	// we backoff as usual, but start from a randomization of noise
	// interval. Once queue is drained, ticker goes through timer
	// stop and subsequent timer start (see `stopTimer() and `startTimer()`),
	// so ticker configuration restored to the initial one.
	q.Ticker.UpdateExpTicker(time.Second, shortTime2, noise)
}

// Try every minute backoff to every 15 minutes
func (q *DeferredQueue) startTimer() {
	q.log.Functionf("startTimer()")
	q.Ticker.UpdateExpTicker(shortTime1, shortTime2, noise)
}

func (q *DeferredQueue) stopTimer() {
	q.log.Functionf("stopTimer()")
	q.Ticker.UpdateRangeTicker(longTime1, longTime2)
}
