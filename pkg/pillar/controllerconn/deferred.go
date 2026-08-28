// Copyright (c) 2018-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Support for deferring sending of messages after a failure

package controllerconn

import (
	"bytes"
	"context"
	"net/http"
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
// The deferred item can be removed from the queue if
// the send failed:
//     queue.RemoveDeferred(key)
//
// An item stays in the queue until the controller accepts it. There are only
// two cases where a message is given up on and lost:
//
//   - The item was created with the `DiscardOnFailure` flag, meaning the payload
//     will be superseded by the next periodic publication of the same key.
//   - The controller responded with a status code which tells that it will
//     reject the very same payload again (see retriableHTTPStatus).
//
// Both are counted, and the counts together with the current backlog are
// reported to the controller as deviceMetric.deferred_queue.
//
// Anything else is retried indefinitely, because for most of what travels this
// queue nothing else re-asserts the state later, so discarding a message would
// leave the controller's view of an object wrong until that object changes
// again. An item being retried is held back by a growing delay and moved behind
// its peers, so it costs one request per retry interval and blocks nothing.
//
// Retrying forever must not be silent, so two conditions are logged as
// warnings: a backlog of more than queueBacklogWarn undelivered messages, and
// an individual payload refused warnAfterAttempts times. Re-publishing the same
// key with unchanged content keeps the retry state of the queued message, so
// that neither the delay nor the count is reset by an object being reported
// again without having changed.
//
// A send failure with no response from the controller at all interrupts the
// queue processing, because the remaining items would fail the same way. The
// queue processing will be repeated by the timer, see the `startTimer()`
// routine. `KickTimerNow` can be called in order to restart queue processing
// immediately.

type deferredItem struct {
	itemType interface{}
	key      string
	buf      *bytes.Buffer
	url      string
	opts     DeferredItemOpts
	// Number of times the controller refused the payload currently in buf.
	attempts int
	// The earliest time of the next send attempt. Zero means "no delay".
	retryAt time.Time
	// When the payload currently in buf was produced.
	createdAt time.Time
}

// DeferredItemOpts defines configurable options for processing a deferred item.
// These options control request behavior such as error handling, network tracing,
// logging, and retry policy across network interfaces.
type DeferredItemOpts struct {
	// BailOnHTTPErr has the same meaning as RequestOptions.BailOnHTTPErr: stop
	// trying the remaining ports once the controller has answered with a 4xx or
	// 5xx status. It does not influence whether the item is retried later - that
	// is decided by the status code alone (see retriableHTTPStatus).
	BailOnHTTPErr bool
	// WithNetTracing enables network tracing for post-mortem troubleshooting purposes.
	WithNetTracing bool
	// DiscardOnFailure, when set to true, discards the item if the send fails instead of
	// keeping it queued for another attempt. Use it for payloads which the next
	// periodic publication of the same key supersedes, so that nothing is gained
	// from retrying this one. All results, including failures, are reported to the
	// sentHandler callback.
	DiscardOnFailure bool
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

// Per-item exponential backoff applied after the controller has refused an item
// with a status code which may not repeat. The queue is kicked on every
// SetDeferred, so without a per-item delay a refused item would be re-attempted
// on every unrelated event.
const minRetryDelay = time.Minute
const maxRetryDelay = time.Minute * 15

// Number of undelivered messages left in the queue at which the backlog is
// called out. Reaching it means reports for a large number of objects are
// waiting, which the controller has no other way of noticing.
const queueBacklogWarn = 50

// Number of refusals of the same payload after which the message is called out,
// and again on every further multiple. With the delay above this is a matter of
// hours, well past any transient trouble at the controller.
const warnAfterAttempts = 20

// DeferredQueue is used so defer send requests and execute them later
// in the background.
type DeferredQueue struct {
	log                    *base.LogObject
	deferredItems          []*deferredItem
	deferredItemsLock      *sync.Mutex
	Ticker                 flextimer.FlexTickerHandle
	priorityCheckFunctions []TypePriorityCheckFunction
	sentHandler            SentHandlerFunction
	ctrlClient             deferredSender
	iteration              int
	// Messages given up on since boot, split by which of the two reasons
	// applied, and when the most recent one was. Guarded by
	// deferredItemsLock, which is what lets Stats() read them.
	droppedRejected   uint64
	droppedSuperseded uint64
	lastDropped       time.Time
}

// DeferredQueueStats is a snapshot of what a queue is holding back and what it
// has given up on since boot.
type DeferredQueueStats struct {
	// Undelivered counts the messages still waiting for the controller.
	Undelivered uint32
	// OldestUndelivered is when the oldest of those payloads was produced.
	// Zero when there are none.
	OldestUndelivered time.Time
	// Rejected counts the messages given up on because the controller refused
	// the payload with a status it would answer the same way again.
	Rejected uint64
	// Superseded counts the messages given up on because the next periodic
	// publication of the same key replaces them.
	Superseded uint64
	// LastDropped is when the most recent message was given up on. Zero when
	// none has been.
	LastDropped time.Time
}

// Add sums another queue's snapshot into this one, so that several queues can
// be reported together.
func (s *DeferredQueueStats) Add(other DeferredQueueStats) {
	s.Undelivered += other.Undelivered
	s.Rejected += other.Rejected
	s.Superseded += other.Superseded
	if !other.OldestUndelivered.IsZero() &&
		(s.OldestUndelivered.IsZero() ||
			other.OldestUndelivered.Before(s.OldestUndelivered)) {
		s.OldestUndelivered = other.OldestUndelivered
	}
	if other.LastDropped.After(s.LastDropped) {
		s.LastDropped = other.LastDropped
	}
}

// Stats returns a snapshot of the queue's backlog and of the messages it has
// given up on.
func (q *DeferredQueue) Stats() DeferredQueueStats {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()

	stats := DeferredQueueStats{
		Rejected:    q.droppedRejected,
		Superseded:  q.droppedSuperseded,
		LastDropped: q.lastDropped,
	}
	for _, item := range q.deferredItems {
		if item.buf == nil {
			continue
		}
		stats.Undelivered++
		if stats.OldestUndelivered.IsZero() ||
			item.createdAt.Before(stats.OldestUndelivered) {
			stats.OldestUndelivered = item.createdAt
		}
	}
	return stats
}

// recordDrop counts a message the queue has given up on. Called from the queue
// processing task, which does not hold deferredItemsLock while sending.
func (q *DeferredQueue) recordDrop(superseded bool) {
	q.deferredItemsLock.Lock()
	defer q.deferredItemsLock.Unlock()

	if superseded {
		q.droppedSuperseded++
	} else {
		q.droppedRejected++
	}
	q.lastDropped = time.Now()
}

// deferredSender is the part of Client which the queue uses to deliver an item.
// Having it as an interface keeps the queue policy exercisable without a network.
type deferredSender interface {
	SendOnAllIntf(ctx context.Context, url string, b *bytes.Buffer,
		opts RequestOptions) (SendRetval, error)
	GetContextForAllIntfFunctions() (context.Context, context.CancelFunc)
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

// retriableHTTPStatus tells whether re-sending the very same payload later has
// any chance of being accepted by a controller which responded with the given
// status code.
//
// Server errors, rate limiting and timeouts are temporary by nature. So is a
// refusal to authenticate or authorize the device: EVE responds to those by
// renewing what the controller rejected - a 403 restarts attestation, a
// certificate problem triggers a fetch of new controller certs - after which
// the same payload is expected to be accepted.
//
// The rest of the 4xx range means the controller objects to the request itself
// and will object to the identical bytes again. 404 in particular is the case
// this distinction was originally introduced for: the controller no longer
// knows about an object the device is still reporting.
func retriableHTTPStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden,
		http.StatusProxyAuthRequired, http.StatusRequestTimeout,
		http.StatusTooManyRequests:
		return true
	}
	return statusCode >= 500 && statusCode < 600
}

// retryDelay returns for how long to hold off the next attempt of an item which
// the controller has refused, doubling with every attempt made so far.
func retryDelay(attempts int) time.Duration {
	delay := minRetryDelay
	for i := 1; i < attempts && delay < maxRetryDelay; i++ {
		delay *= 2
	}
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	return delay
}

// allSuppressLogs tells whether every one of the items asked for send problems
// to be kept out of the log.
func allSuppressLogs(items []*deferredItem) bool {
	for _, item := range items {
		if !item.opts.SuppressLogs {
			return false
		}
	}
	return true
}

// sameContent tells whether two queued payloads carry identical bytes.
func sameContent(a, b *bytes.Buffer) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Bytes(), b.Bytes())
}

// itemDisposition says what should happen to a deferred item after an attempt
// to send it.
type itemDisposition int

const (
	// itemDone - the item leaves the queue, either because the controller
	// accepted it or because it is not worth offering again.
	itemDone itemDisposition = iota
	// itemRetry - the item stays in the queue for a later attempt.
	itemRetry
	// itemStopPass - the controller could not be reached at all; the item stays
	// in the queue and the rest of this pass is abandoned.
	itemStopPass
)

// reportSendResult passes the outcome of a send attempt to the sentHandler
// callback. A failure is always reported with a non-zero status, since
// SenderStatusNone means success to the callback.
func (q *DeferredQueue) reportSendResult(item *deferredItem, rv SendRetval,
	failed bool) {
	if q.sentHandler == nil {
		return
	}
	if failed && rv.Status == types.SenderStatusNone {
		rv.Status = types.SenderStatusFailed
	}
	q.sentHandler(item.itemType, item.buf, rv.Status, rv.TracedReqs)
}

// sendItem makes a single attempt to send a deferred item and returns what
// should happen to the item afterwards.
func (q *DeferredQueue) sendItem(ctx context.Context,
	item *deferredItem) itemDisposition {

	rv, err := q.ctrlClient.SendOnAllIntf(ctx, item.url, item.buf,
		RequestOptions{
			SuppressLogs:     item.opts.SuppressLogs,
			WithNetTracing:   item.opts.WithNetTracing,
			NetTraceFolder:   types.NetTraceFolder,
			BailOnHTTPErr:    item.opts.BailOnHTTPErr,
			Iteration:        q.iteration,
			AllowLoopbackDNS: item.opts.AllowLoopbackDNS,
		})

	//try with another interface next time
	q.iteration++

	// An airgapped device is not expected to reach the controller at all, so it
	// asks for the noise to be kept out of the log.
	errorLog := q.log.Errorf
	warnLog := q.log.Warnf
	noticeLog := q.log.Noticef
	if item.opts.SuppressLogs {
		errorLog = q.log.Tracef
		warnLog = q.log.Tracef
		noticeLog = q.log.Tracef
	}

	status := rv.LastHTTPStatusCode
	// A status code means that the controller was reached and answered, so the
	// failure belongs to this item alone and the rest of the queue is still
	// worth a try.
	refused := status >= 400 && status < 600

	switch {
	case refused:
		// Logged below, once the disposition of the item is known.
	case err != nil:
		q.log.Functionf("handleDeferred: for %s status %d failed %s",
			item.key, rv.Status, err)
	case rv.Status != types.SenderStatusNone:
		q.log.Functionf("handleDeferred: for %s received unexpected status %d",
			item.key, rv.Status)
	default:
		q.reportSendResult(item, rv, false)
		return itemDone
	}

	q.reportSendResult(item, rv, true)
	switch {
	case !refused:
		if item.opts.DiscardOnFailure {
			q.recordDrop(true)
			return itemDone
		}
		return itemStopPass

	case item.opts.DiscardOnFailure:
		q.log.Functionf("handleDeferred: for %s dropping superseded message, "+
			"controller responded %d %s", item.key, status,
			http.StatusText(status))
		q.recordDrop(true)
		return itemDone

	case !retriableHTTPStatus(status):
		// Nothing else re-asserts most of what travels this queue, so record
		// the loss at a severity that reaches the controller and the operator.
		errorLog("handleDeferred: for %s dropping message, controller "+
			"responded %d %s", item.key, status, http.StatusText(status))
		q.recordDrop(false)
		return itemDone

	default:
		item.attempts++
		item.retryAt = time.Now().Add(retryDelay(item.attempts))
		// A message refused this many times is no longer a passing hiccup, and
		// since it is never given up on, saying so is the only way anyone finds
		// out that this state is not reaching the controller.
		logRetry := noticeLog
		if item.attempts%warnAfterAttempts == 0 {
			logRetry = warnLog
		}
		logRetry("handleDeferred: for %s controller responded %d %s, "+
			"attempt %d, retrying in %v", item.key, status,
			http.StatusText(status), item.attempts,
			retryDelay(item.attempts))
		return itemRetry
	}
}

// handleDeferred try to send all deferred items which are due
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
			if item.buf.Len() == 0 {
				q.log.Functionf("handleDeferred: Zero length deferred item for %s",
					key)
				continue
			}
			if time.Now().Before(item.retryAt) {
				q.log.Functionf("handleDeferred: for %s next attempt in %v",
					key, time.Until(item.retryAt).Round(time.Second))
				continue
			}
			q.log.Functionf("handleDeferred: Trying to send for %s", key)

			switch q.sendItem(ctx, item) {
			case itemDone:
				item.buf = nil
			case itemRetry:
			case itemStopPass:
				exit = true
			}
			if exit {
				break
			}
		}
		if exit {
			break
		}
	}

	// Keep the not sent requests, with the ones waiting out a backoff at the
	// tail, so that an item the controller keeps refusing cannot hold up the
	// items behind it.
	var notSentReqs, backoffReqs []*deferredItem
	now := time.Now()
	for _, el := range reqs {
		switch {
		case el.buf == nil:
			// Sent or given up on.
		case el.retryAt.After(now):
			backoffReqs = append(backoffReqs, el)
		default:
			notSentReqs = append(notSentReqs, el)
		}
	}
	notSentReqs = append(notSentReqs, backoffReqs...)

	if len(notSentReqs) > 0 {
		// Log the content of the rest in the queue. A backlog this long means
		// the reports for many objects are undelivered, which is worth saying
		// out loud once per pass - unless every one of them asked for quiet,
		// as an airgapped device does.
		logRest := q.log.Functionf
		if len(notSentReqs) > queueBacklogWarn && !allSuppressLogs(notSentReqs) {
			logRest = q.log.Warnf
		}
		logRest("handleDeferred() the rest to be sent: %d", len(notSentReqs))
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
// for the object. Replacing an item also resets the retry state, since
// the controller has not seen the new payload yet.
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
		key:       key,
		itemType:  itemType,
		buf:       buf,
		url:       url,
		opts:      opts,
		createdAt: time.Now(),
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
		// Re-publishing the very same bytes is the same message, so it inherits
		// the retry state: an object whose reported state has not actually
		// changed must not restart the backoff on every publication, nor hide
		// how long the message has been undeliverable.
		if sameContent(q.deferredItems[ind].buf, buf) {
			item.attempts = q.deferredItems[ind].attempts
			item.retryAt = q.deferredItems[ind].retryAt
			item.createdAt = q.deferredItems[ind].createdAt
		}
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
