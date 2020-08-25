// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Support for deferring sending of messages after a failure

package zedcloud

import (
	"bytes"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"time"
)

// Example usage:
// deferredChan := zedcloud.InitDeferred(zedcloudCtx)
// select {
//      case change := <- deferredChan:
//		zedcloud.HandleDeferred(zedcloudCtx, change)
// Before or after sending success call:
//	zedcloud.RemoveDeferred(key)
// After failure call
// 	zedcloud.SetDeferred(key, buf, size, url, zedcloudCtx)
// or AddDeferred to build a queue for each key

type deferredItem struct {
	buf           *bytes.Buffer
	size          int64
	url           string
	zedcloudCtx   *ZedCloudContext
	bailOnHTTPErr bool // Return 4xx and 5xx without trying other interfaces
}

type deferredItemList struct {
	list []deferredItem
}

const longTime1 = time.Hour * 24
const longTime2 = time.Hour * 48

// DeferredContext is part of ZedcloudContext
type DeferredContext struct {
	deferredItems map[string]deferredItemList
	ticker        flextimer.FlexTickerHandle
}

// GetDeferredChan creates and returns a channel to the caller
// We always keep a flextimer running so that we can return
// the associated channel. We adjust the times when we start and stop
// the timer.
func GetDeferredChan(zedcloudCtx *ZedCloudContext) <-chan time.Time {
	zedcloudCtx.deferredCtx = DeferredContext{
		deferredItems: make(map[string]deferredItemList),
		ticker:        flextimer.NewRangeTicker(longTime1, longTime2),
	}
	return zedcloudCtx.deferredCtx.ticker.C
}

// Try to send all deferred items. Give up if any one fails
// Stop timer if map becomes empty
// Returns true when there are no more deferred items
func HandleDeferred(zedcloudCtx *ZedCloudContext, event time.Time, spacing time.Duration) bool {

	return zedcloudCtx.deferredCtx.handleDeferred(zedcloudCtx.log, event, spacing)
}

func (ctx *DeferredContext) handleDeferred(log *base.LogObject, event time.Time,
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
			if item.buf.Len() == 0 {
				log.Errorf("Zero length defered item for %s",
					key)
				continue
			}
			log.Infof("Trying to send for %s item %d data size %d\n",
				key, i, item.size)
			resp, _, _, err := SendOnAllIntf(item.zedcloudCtx, item.url,
				item.size, item.buf, iteration, item.bailOnHTTPErr)
			if item.bailOnHTTPErr && resp != nil &&
				resp.StatusCode >= 400 && resp.StatusCode < 600 {
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
		stopTimer(log, ctx)
	}
	log.Infof("HandleDeferred() done map %d\n", len(ctx.deferredItems))
	return len(ctx.deferredItems) == 0
}

// Check if there are any deferred items for this key
func HasDeferred(zedcloudCtx *ZedCloudContext, key string) bool {
	return zedcloudCtx.deferredCtx.hasDeferred(zedcloudCtx.log, key)
}

func (ctx *DeferredContext) hasDeferred(log *base.LogObject, key string) bool {

	log.Debugf("HasDeferred(%s) map %d\n", key, len(ctx.deferredItems))
	_, ok := ctx.deferredItems[key]
	return ok
}

// Remove any item for the specific key. If no items left then stop timer.
func RemoveDeferred(zedcloudCtx *ZedCloudContext, key string) {
	zedcloudCtx.deferredCtx.removeDeferred(zedcloudCtx.log, key)
}

func (ctx *DeferredContext) removeDeferred(log *base.LogObject, key string) {

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
		stopTimer(log, ctx)
	}
}

// Replace any item for the specified key. If timer not running start it
// SetDeferred uses the key for identifying the channel. Please note that
// for deviceUUID key is used for attestUrl, which is not the same for
// other Urls, where in other caes, the key is very specific for the object
//  and object type
func SetDeferred(zedcloudCtx *ZedCloudContext, key string, buf *bytes.Buffer,
	size int64, url string, bailOnHTTPErr bool) {

	zedcloudCtx.deferredCtx.setDeferred(zedcloudCtx, key, buf, size, url, bailOnHTTPErr)
}

func (ctx *DeferredContext) setDeferred(zedcloudCtx *ZedCloudContext,
	key string, buf *bytes.Buffer, size int64, url string, bailOnHTTPErr bool) {

	log := zedcloudCtx.log
	log.Infof("SetDeferred(%s) size %d map %d\n",
		key, size, len(ctx.deferredItems))
	if len(ctx.deferredItems) == 0 {
		startTimer(log, ctx)
	}
	_, ok := ctx.deferredItems[key]
	if ok {
		log.Debugf("Replacing key %s\n", key)
	} else {
		log.Debugf("Adding key %s\n", key)
	}
	item := deferredItem{
		buf:           buf,
		size:          size,
		url:           url,
		zedcloudCtx:   zedcloudCtx,
		bailOnHTTPErr: bailOnHTTPErr,
	}
	l := deferredItemList{}
	l.list = append(l.list, item)
	ctx.deferredItems[key] = l
}

// Add to slice for this key
func AddDeferred(zedcloudCtx *ZedCloudContext, key string, buf *bytes.Buffer,
	size int64, url string, bailOnHTTPErr bool) {

	zedcloudCtx.deferredCtx.addDeferred(zedcloudCtx, key, buf, size, url, bailOnHTTPErr)
}

func (ctx *DeferredContext) addDeferred(zedcloudCtx *ZedCloudContext,
	key string, buf *bytes.Buffer, size int64, url string, bailOnHTTPErr bool) {

	log := zedcloudCtx.log
	log.Infof("AddDeferred(%s) size %d map %d\n", key,
		size, len(ctx.deferredItems))
	if len(ctx.deferredItems) == 0 {
		startTimer(log, ctx)
	}
	l, ok := ctx.deferredItems[key]
	if ok {
		log.Debugf("Appending to key %s have %d\n", key, len(l.list))
	} else {
		log.Debugf("Adding key %s\n", key)
	}
	item := deferredItem{
		buf:           buf,
		size:          size,
		url:           url,
		zedcloudCtx:   zedcloudCtx,
		bailOnHTTPErr: bailOnHTTPErr,
	}
	l.list = append(l.list, item)
	ctx.deferredItems[key] = l
}

// Try every minute backoff to every 15 minutes
func startTimer(log *base.LogObject, ctx *DeferredContext) {

	log.Infof("startTimer()\n")
	min := 1 * time.Minute
	max := 15 * time.Minute
	ctx.ticker.UpdateExpTicker(min, max, 0.3)
}

func stopTimer(log *base.LogObject, ctx *DeferredContext) {

	log.Infof("stopTimer()\n")
	ctx.ticker.UpdateRangeTicker(longTime1, longTime2)
}
