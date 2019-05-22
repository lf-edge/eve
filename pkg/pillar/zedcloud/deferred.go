// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Support for deferring sending of messages after a failure

package zedcloud

import (
	"bytes"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	log "github.com/sirupsen/logrus"
	"time"
)

// Example usage:
// deferredChan := zedcloud.InitDeferred()
// select {
//      case change := <- deferredChan:
//		zedcloud.HandleDeferred(change)
// Before or after sending success call:
//	zedcloud.RemoveDeferred(key)
// After failure call
// 	zedcloud.SetDeferred(key, buf, size, url, zedcloudCtx)
// or AddDeferred to build a queue for each key

type deferredItem struct {
	buf         *bytes.Buffer
	size        int64
	url         string
	zedcloudCtx ZedCloudContext
	return400   bool
}

type deferredItemList struct {
	list []deferredItem
}

const longTime1 = time.Hour * 24
const longTime2 = time.Hour * 48

// Some day we might return this; right now only for the defaultCtx
type DeferredContext struct {
	deferredItems map[string]deferredItemList
	ticker        flextimer.FlexTickerHandle
}

// From first InitDeferred
var defaultCtx *DeferredContext

// Create and return a channel to the caller
func InitDeferred() <-chan time.Time {
	if defaultCtx != nil {
		log.Fatal("InitDeferred called twice")
	}
	defaultCtx = initImpl()
	return defaultCtx.ticker.C
}

func initImpl() *DeferredContext {
	ctx := new(DeferredContext)
	ctx.deferredItems = make(map[string]deferredItemList)
	// We always keep a flextimer running so that we can return
	// the associated channel. We adjust the times when we start and stop
	// the timer.
	ctx.ticker = flextimer.NewRangeTicker(longTime1, longTime2)
	return ctx
}

// Try to send all deferred items. Give up if any one fails
// Stop timer if map becomes empty
// Returns true when there are no more deferred items
func HandleDeferred(event time.Time, spacing time.Duration) bool {

	if defaultCtx == nil {
		log.Fatal("HandleDeferred no defaultCtx")
	}
	return defaultCtx.handleDeferred(event, spacing)
}

func (ctx *DeferredContext) handleDeferred(event time.Time,
	spacing time.Duration) bool {

	log.Infof("HandleDeferred(%v, %v) map %d\n",
		event, spacing, len(ctx.deferredItems))
	iteration := 0 // Do some load spreading
	for key, l := range ctx.deferredItems {
		log.Infof("Trying to send for %s items %d\n", key, len(l.list))
		failed := false
		for i, item := range l.list {
			if item.buf == nil {
				continue
			}
			log.Infof("Trying to send for %s item %d data size %d\n",
				key, i, item.size)
			resp, _, _, err := SendOnAllIntf(item.zedcloudCtx, item.url,
				item.size, item.buf, iteration, item.return400)
			if item.return400 && resp != nil &&
				resp.StatusCode == 400 {
				log.Infof("HandleDeferred: for %s ignore code %d\n",
					key, resp.StatusCode)
			} else if err != nil {
				log.Infof("HandleDeferred: for %s failed %s\n",
					key, err)
				failed = true
				break
			}
			item.buf = nil
		}
		if failed {
			break
		} else {
			delete(ctx.deferredItems, key)
			iteration += 1
			// XXX sleeping in main thread
			if len(ctx.deferredItems) != 0 && spacing != 0 {
				log.Infof("HandleDeferred sleeping %v\n",
					spacing)
				time.Sleep(spacing)
			}
		}
	}
	if len(ctx.deferredItems) == 0 {
		stopTimer(ctx)
	}
	log.Infof("HandleDeferred() done map %d\n", len(ctx.deferredItems))
	return len(ctx.deferredItems) == 0
}

// Check if there are any deferred items for this key
func HasDeferred(key string) bool {
	if defaultCtx == nil {
		log.Fatal("HasDeferred no defaultCtx")
	}
	return defaultCtx.hasDeferred(key)
}

func (ctx *DeferredContext) hasDeferred(key string) bool {

	log.Debugf("HasDeferred(%s) map %d\n", key, len(ctx.deferredItems))
	_, ok := ctx.deferredItems[key]
	return ok
}

// Remove any item for the specific key. If no items left then stop timer.
func RemoveDeferred(key string) {
	if defaultCtx == nil {
		log.Fatal("RemoveDeferred no defaultCtx")
	}
	defaultCtx.removeDeferred(key)
}

func (ctx *DeferredContext) removeDeferred(key string) {

	log.Debugf("RemoveDeferred(%s) map %d\n", key, len(ctx.deferredItems))
	_, ok := ctx.deferredItems[key]
	if !ok {
		// Normal case
		log.Debugf("removeDeferred: Non-existing key %s\n", key)
		return
	}
	log.Debugf("Deleting key %s\n", key)
	delete(ctx.deferredItems, key)

	if len(ctx.deferredItems) == 0 {
		stopTimer(ctx)
	}
}

// Replace any item for the specified key. If timer not running start it
func SetDeferred(key string, buf *bytes.Buffer, size int64, url string,
	zedcloudCtx ZedCloudContext, return400 bool) {

	if defaultCtx == nil {
		log.Fatal("SetDeferred no defaultCtx")
	}
	defaultCtx.setDeferred(key, buf, size, url, zedcloudCtx, return400)
}

func (ctx *DeferredContext) setDeferred(key string, buf *bytes.Buffer,
	size int64, url string, zedcloudCtx ZedCloudContext, return400 bool) {

	log.Infof("SetDeferred(%s) size %d map %d\n",
		key, size, len(ctx.deferredItems))
	if len(ctx.deferredItems) == 0 {
		startTimer(ctx)
	}
	_, ok := ctx.deferredItems[key]
	if ok {
		log.Debugf("Replacing key %s\n", key)
	} else {
		log.Debugf("Adding key %s\n", key)
	}
	item := deferredItem{
		buf:         buf,
		size:        size,
		url:         url,
		zedcloudCtx: zedcloudCtx,
		return400:   return400,
	}
	l := deferredItemList{}
	l.list = append(l.list, item)
	ctx.deferredItems[key] = l
}

// Add to slice for this key
func AddDeferred(key string, buf *bytes.Buffer, size int64, url string,
	zedcloudCtx ZedCloudContext, return400 bool) {

	if defaultCtx == nil {
		log.Fatal("SetDeferred no defaultCtx")
	}
	defaultCtx.addDeferred(key, buf, size, url, zedcloudCtx, return400)
}

func (ctx *DeferredContext) addDeferred(key string, buf *bytes.Buffer,
	size int64, url string, zedcloudCtx ZedCloudContext, return400 bool) {

	log.Infof("AddDeferred(%s) size %d map %d\n", key,
		size, len(ctx.deferredItems))
	if len(ctx.deferredItems) == 0 {
		startTimer(ctx)
	}
	l, ok := ctx.deferredItems[key]
	if ok {
		log.Debugf("Appending to key %s have %d\n", key, len(l.list))
	} else {
		log.Debugf("Adding key %s\n", key)
	}
	item := deferredItem{
		buf:         buf,
		size:        size,
		url:         url,
		zedcloudCtx: zedcloudCtx,
		return400:   return400,
	}
	l.list = append(l.list, item)
	ctx.deferredItems[key] = l
}

// Try every minute backoff to every 15 minutes
func startTimer(ctx *DeferredContext) {

	log.Infof("startTimer()\n")
	min := 1 * time.Minute
	max := 15 * time.Minute
	ctx.ticker.UpdateExpTicker(min, max, 0.3)
}

func stopTimer(ctx *DeferredContext) {

	log.Infof("stopTimer()\n")
	ctx.ticker.UpdateRangeTicker(longTime1, longTime2)
}
