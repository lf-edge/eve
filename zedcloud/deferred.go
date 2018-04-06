// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Support for deferring sending of messages after a failure

package zedcloud

import (
	"bytes"
	"github.com/zededa/go-provision/flextimer"
	"log"
	"time"
)

// Example usage:
// deferredChan := zedcloud.InitDeferred()
// select {
//      case change := <- deferredChan:
//		zedcloud.HandleDeferred(change)
// Before or after sending success call:
//	zedcloud.RemoveDeferred(uuidStr)
// After failure call
// 	zedcloud.SetDeferred(uuidStr, data, url, zedcloudCtx)

var debug = true // XXX or use zedcloudCtx.Debug?

var deferredChan chan string

type deferredItem struct {
	data        []byte
	url         string
	zedcloudCtx ZedCloudContext
}

var deferredItems map[string]deferredItem

const longTime1 = time.Hour * 24
const longTime2 = time.Hour * 48

// We always keep a flextimer running so that we can return
// the associated channel. We adjust the times when we start and stop
// the timer.
var ticker = flextimer.NewRangeTicker(longTime1, longTime2)

// Create and return a channel to the
func InitDeferred() <-chan time.Time {
	deferredItems = make(map[string]deferredItem)
	return ticker.C
}

// Try to send all deferred items. Give up if any one fails
// Stop timer is map becomes empty
func HandleDeferred(event time.Time) {
	log.Printf("HandleDeferred(%v) map %d\n",
		event, len(deferredItems))
	iteration := 0 // XXX
	for key, item := range deferredItems {
		log.Printf("Trying to send for %s\n", key)
		_, _, err := SendOnAllIntf(item.zedcloudCtx, item.url,
			int64(len(item.data)), bytes.NewBuffer(item.data),
			iteration)
		if err != nil {
			log.Printf("HandleDeferred: for %s failed %s\n",
				key, err)
			break
		}
		delete(deferredItems, key)
		iteration += 1
	}
	if len(deferredItems) == 0 {
		stopTimer()
	}
}

// Check if there are any deferred items for this key
func HasDeferred(key string) bool {
	if debug {
		log.Printf("HasDeferred(%s) map %d\n",
			key, len(deferredItems))
	}
	_, ok := deferredItems[key]
	return ok
}

// Remove any item for the specific key. If no items left then stop timer.
func RemoveDeferred(key string) {
	if debug {
		log.Printf("RemoveDeferred(%s) map %d\n",
			key, len(deferredItems))
	}
	_, ok := deferredItems[key]
	if !ok {
		if debug {
			log.Printf("Non-existing key %s\n", key)
		}
		return
	}
	if debug {
		log.Printf("Deleting key %s\n", key)
	}
	delete(deferredItems, key)

	if len(deferredItems) == 0 {
		stopTimer()
	}
}

// Replace any item for the specified key. If timer not running start it
func SetDeferred(key string, data []byte, url string,
	zedcloudCtx ZedCloudContext) {

	log.Printf("QueueDeferred(%s) map %d\n", key, len(deferredItems))
	if len(deferredItems) == 0 {
		startTimer()
	}
	if debug {
		_, ok := deferredItems[key]
		if ok {
			log.Printf("Replacing key %s\n", key)
		} else {
			log.Printf("Adding key %s\n", key)
		}
	}
	deferredItems[key] = deferredItem{
		data:        data,
		url:         url,
		zedcloudCtx: zedcloudCtx,
	}
}

// Try every minute backoff to every 15 minutes
func startTimer() {
	if debug {
		log.Printf("startTimer()\n")
	}
	min := 1 * time.Minute
	max := 15 * time.Minute
	ticker.UpdateExpTicker(min, max, 0.3)
}

func stopTimer() {
	if debug {
		log.Printf("stopTimer()\n")
	}
	ticker.UpdateRangeTicker(longTime1, longTime2)
}
