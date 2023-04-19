// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Support for deferring sending of messages after a failure

package zedcloud

import (
	"bytes"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Example usage:
// ctx := zedcloud.CreateDeferredCtx(zedcloudCtx, ...)
// select {
//      case change := <- ctx.Ticker.C:
//          ctx.HandleDeferred(...)
// Before or after sending success call:
//     ctx.RemoveDeferred(key)
// After failure call
//     ctx.SetDeferred(key, buf, size, ...)

type deferredItem struct {
	itemType       interface{}
	key            string
	buf            *bytes.Buffer
	size           int64
	url            string
	bailOnHTTPErr  bool // Return 4xx and 5xx without trying other interfaces
	withNetTracing bool
	ignoreErr      bool
}

const maxTimeToHandleDeferred = time.Minute
const longTime1 = time.Hour * 24
const longTime2 = time.Hour * 48

// DeferredContext is part of ZedcloudContext
type DeferredContext struct {
	deferredItems          []*deferredItem
	Ticker                 flextimer.FlexTickerHandle
	priorityCheckFunctions []TypePriorityCheckFunction
	lock                   *sync.Mutex
	sentHandler            *SentHandlerFunction
	zedcloudCtx            *ZedCloudContext
	iteration              int
}

// TypePriorityCheckFunction returns true in case of find type with high priority
type TypePriorityCheckFunction func(itemType interface{}) bool

// SentHandlerFunction allow doing something with data if it was handled
// result indicates sending result
type SentHandlerFunction func(
	itemType interface{}, data *bytes.Buffer, result types.SenderStatus,
	traces []netdump.TracedNetRequest)

// CreateDeferredCtx creates and returns a deferred context
// We always keep a flextimer running so that we can return
// the associated channel. We adjust the times when we start and stop
// the timer.
// sentHandler is callback which will be run on successful sent
// priorityCheckFunctions may be added to send item with matched itemType firstly
// default function at the end of priorityCheckFunctions added to serve non-priority items
func CreateDeferredCtx(zedcloudCtx *ZedCloudContext, sentHandler *SentHandlerFunction,
	priorityCheckFunctions ...TypePriorityCheckFunction) *DeferredContext {
	// Default "accept all" priority
	priorityCheckFunctions = append(priorityCheckFunctions,
		func(obj interface{}) bool {
			return true
		})

	deferredCtx := DeferredContext{
		lock:                   &sync.Mutex{},
		Ticker:                 flextimer.NewRangeTicker(longTime1, longTime2),
		sentHandler:            sentHandler,
		priorityCheckFunctions: priorityCheckFunctions,
		zedcloudCtx:            zedcloudCtx,
	}

	return &deferredCtx
}

// HandleDeferred try to send all deferred items (or only one if sendOne set). Give up if any one fails
// Stop timer if map becomes empty
// Returns true when there are no more deferred items
func (ctx *DeferredContext) HandleDeferred(event time.Time,
	spacing time.Duration, sendOne bool) bool {
	ctx.lock.Lock()
	reqs := ctx.deferredItems
	ctx.deferredItems = []*deferredItem{}
	ctx.lock.Unlock()

	log := ctx.zedcloudCtx.log

	if len(reqs) == 0 {
		return true
	}

	log.Functionf("HandleDeferred(%v, %v) items %d", event, spacing, len(reqs))

	exit := false
	sent := 0
	ctxWork, cancel := GetContextForAllIntfFunctions(ctx.zedcloudCtx)
	defer cancel()
	for _, f := range ctx.priorityCheckFunctions {
		for _, item := range reqs {
			key := item.key
			//check with current priority function
			if !f(item.itemType) {
				continue
			}
			if item.buf == nil {
				continue
			}
			log.Functionf("handleDeferred: Trying to send for %s", key)
			if item.buf.Len() == 0 {
				log.Functionf("handleDeferred: Zero length deferred item for %s",
					key)
				continue
			}

			//SenderStatusNone indicates no problems
			rv, err := SendOnAllIntf(ctxWork, ctx.zedcloudCtx, item.url,
				item.size, item.buf, ctx.iteration, item.bailOnHTTPErr, item.withNetTracing)
			// We check StatusCode before err since we do not want
			// to exit the loop just because some message is rejected
			// by the controller.
			if item.bailOnHTTPErr && rv.HTTPResp != nil &&
				rv.HTTPResp.StatusCode >= 400 && rv.HTTPResp.StatusCode < 600 {
				log.Functionf("handleDeferred: for %s ignore code %d",
					key, rv.HTTPResp.StatusCode)
			} else if err != nil {
				log.Functionf("handleDeferred: for %s status %d failed %s",
					key, rv.Status, err)
				exit = !item.ignoreErr
				// Make sure we pass a non-zero result to the sentHandler.
				if rv.Status == types.SenderStatusNone {
					rv.Status = types.SenderStatusFailed
				}
			} else if rv.Status != types.SenderStatusNone {
				log.Functionf("handleDeferred: for %s received unexpected status %d",
					key, rv.Status)
				exit = !item.ignoreErr
			}
			if ctx.sentHandler != nil {
				f := *ctx.sentHandler
				f(item.itemType, item.buf, rv.Status, rv.TracedReqs)
			}

			//try with another interface next time
			ctx.iteration++

			if exit {
				break
			}
			item.buf = nil
			sent++

			if sendOne {
				exit = true
				break
			}

			if time.Since(event) > maxTimeToHandleDeferred {
				log.Warnf("handleDeferred: took too long time %v",
					time.Since(event))
				exit = true
				break
			}

			// XXX sleeping in main thread
			if len(reqs)-sent != 0 && spacing != 0 {
				log.Functionf("handleDeferred: sleeping %v",
					spacing)
				time.Sleep(spacing)
			}
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

	// Log the content of the rest in the queue
	log.Noticef("handleDeferred() the rest to be sent: %d",
		len(notSentReqs))
	if ctx.sentHandler != nil {
		for _, item := range notSentReqs {
			f := *ctx.sentHandler
			f(item.itemType, item.buf, types.SenderStatusDebug, nil)
		}
	}

	ctx.lock.Lock()
	// Merge with the incoming requests, recently added are in the tail
	ctx.deferredItems = append(notSentReqs, ctx.deferredItems...)
	if len(ctx.deferredItems) == 0 {
		stopTimer(log, ctx)
	}
	ctx.lock.Unlock()

	allSent := len(notSentReqs) == 0

	return allSent
}

// SetDeferred sets or replaces any item for the specified key and
// starts the timer. Key is used for identifying the channel. Please
// note that for deviceUUID key is used for attestUrl, which is not the
// same for other Urls, where in other case, the key is very specific
// for the object. If @ignoreErr is true the queue processing is not
// stopped on any error and will continue, although all errors will be
// passed to @sentHandler callback (see the CreateDeferredCtx()).
func (ctx *DeferredContext) SetDeferred(
	key string, buf *bytes.Buffer, size int64, url string, bailOnHTTPErr,
	withNetTracing, ignoreErr bool, itemType interface{}) {
	ctx.lock.Lock()
	defer ctx.lock.Unlock()

	log := ctx.zedcloudCtx.log
	log.Functionf("SetDeferred(%s) size %d items %d",
		key, size, len(ctx.deferredItems))
	if len(ctx.deferredItems) == 0 {
		startTimer(log, ctx)
	}
	item := deferredItem{
		key:            key,
		itemType:       itemType,
		buf:            buf,
		size:           size,
		url:            url,
		bailOnHTTPErr:  bailOnHTTPErr,
		withNetTracing: withNetTracing,
		ignoreErr:      ignoreErr,
	}
	found := false
	ind := 0
	var itemList *deferredItem
	for ind, itemList = range ctx.deferredItems {
		if itemList.key == key {
			found = true
			break
		}
	}
	if found {
		log.Tracef("Replacing key %s", key)
		ctx.deferredItems[ind] = &item
	} else {
		log.Tracef("Adding key %s", key)
		ctx.deferredItems = append(ctx.deferredItems, &item)
	}
}

// RemoveDeferred removes key from deferred items if exists
func (ctx *DeferredContext) RemoveDeferred(key string) {
	ctx.lock.Lock()
	defer ctx.lock.Unlock()

	log := ctx.zedcloudCtx.log
	log.Functionf("RemoveDeferred(%s) items %d",
		key, len(ctx.deferredItems))

	for ind, itemList := range ctx.deferredItems {
		if itemList.key == key {
			log.Tracef("Deleting key %s", key)
			ctx.deferredItems = append(ctx.deferredItems[:ind], ctx.deferredItems[ind+1:]...)
			break
		}
	}
	if len(ctx.deferredItems) == 0 {
		stopTimer(log, ctx)
	}
}

// KickTimer kicks the timer for immediate execution
func (ctx *DeferredContext) KickTimer() {
	ctx.Ticker.TickNow()
}

// Try every minute backoff to every 15 minutes
func startTimer(log *base.LogObject, ctx *DeferredContext) {

	log.Functionf("startTimer()")
	min := 1 * time.Minute
	max := 15 * time.Minute
	ctx.Ticker.UpdateExpTicker(min, max, 0.3)
}

func stopTimer(log *base.LogObject, ctx *DeferredContext) {

	log.Functionf("stopTimer()")
	ctx.Ticker.UpdateRangeTicker(longTime1, longTime2)
}
