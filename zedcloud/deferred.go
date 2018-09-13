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
//	zedcloud.RemoveDeferred(key)
// After failure call
// 	zedcloud.SetDeferred(key, data, url, zedcloudCtx)
// or AddDeferred to build a queue for each key

// XXX pass pointer to debug for dynamic?
var debug = false // XXX or use zedcloudCtx.Debug?

var deferredChan chan string

type deferredItem struct {
	data        []byte
	url         string
	zedcloudCtx ZedCloudContext
	ignore400   bool
}

type deferredItemList struct {
	list []deferredItem
}

var deferredItems map[string]deferredItemList

const longTime1 = time.Hour * 24
const longTime2 = time.Hour * 48

// We always keep a flextimer running so that we can return
// the associated channel. We adjust the times when we start and stop
// the timer.
var ticker = flextimer.NewRangeTicker(longTime1, longTime2)

// Create and return a channel to the
// XXX need to return a struct with a chan plus debugPtr??
// Do callers of HandleDeferred have ctx?
func InitDeferred() <-chan time.Time {
	deferredItems = make(map[string]deferredItemList)
	return ticker.C
}

// Try to send all deferred items. Give up if any one fails
// Stop timer is map becomes empty
func HandleDeferred(event time.Time) {
	log.Printf("HandleDeferred(%v) map %d\n",
		event, len(deferredItems))
	iteration := 0 // Do some load spreading
	for key, l := range deferredItems {
		log.Printf("Trying to send for %s len %d\n", key, len(l.list))
		failed := false
		for i, item := range l.list {
			if item.data == nil {
				continue
			}
			log.Printf("Trying to send for %s item %d data len %d\n",
				key, i, len(item.data))
			resp, _, err := SendOnAllIntf(item.zedcloudCtx, item.url,
				int64(len(item.data)), bytes.NewBuffer(item.data),
				iteration, item.ignore400)
			if item.ignore400 && resp != nil &&
				resp.StatusCode >= 400 && resp.StatusCode < 500 {
				log.Printf("HandleDeferred: for %s ignore code %d\n",
					key, resp.StatusCode)
			} else if err != nil {
				log.Printf("HandleDeferred: for %s failed %s\n",
					key, err)
				failed = true
				break
			}
			item.data = nil
		}
		if failed {
			break
		} else {
			delete(deferredItems, key)
			iteration += 1
		}
	}
	if len(deferredItems) == 0 {
		stopTimer()
	}
	log.Printf("HandleDeferred() done map %d\n", len(deferredItems))
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
	zedcloudCtx ZedCloudContext, ignore400 bool) {

	log.Printf("SetDeferred(%s) map %d\n", key, len(deferredItems))
	if len(deferredItems) == 0 {
		startTimer()
	}
	_, ok := deferredItems[key]
	if debug {
		if ok {
			log.Printf("Replacing key %s\n", key)
		} else {
			log.Printf("Adding key %s\n", key)
		}
	}
	item := deferredItem{
		data:        data,
		url:         url,
		zedcloudCtx: zedcloudCtx,
		ignore400:   ignore400,
	}
	l := deferredItemList{}
	l.list = append(l.list, item)
	deferredItems[key] = l
}

// Add to slice for this key
func AddDeferred(key string, data []byte, url string,
	zedcloudCtx ZedCloudContext, ignore400 bool) {

	log.Printf("AddDeferred(%s) map %d\n", key, len(deferredItems))
	if len(deferredItems) == 0 {
		startTimer()
	}
	l, ok := deferredItems[key]
	if debug {
		if ok {
			log.Printf("Appening to key %s len %d\n",
				key, len(l.list))
		} else {
			log.Printf("Adding key %s\n", key)
		}
	}
	item := deferredItem{
		data:        data,
		url:         url,
		zedcloudCtx: zedcloudCtx,
		ignore400:   ignore400,
	}
	l.list = append(l.list, item)
	deferredItems[key] = l
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
