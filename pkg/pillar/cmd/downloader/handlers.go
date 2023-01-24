// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Notify simple struct to pass notification messages
type Notify struct{}

// CancelChannel is the type we send over a channel for the per-download cancels
type CancelChannel chan Notify

type downloadHandler struct {
	// We have one goroutine per provisioned domU object.
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key().

	handlers map[string]*handlerChannels
}

// updateChan is used to send notifications about config (add and updates)
// receiveChan is passed to the networking code so that it can feed
// back a per-operation cancel channel, which we use if we need to cancel.
// cancelChan is used when refcount goes from N->0 to cancel
// pending downloads
// Both update and receive channels are closed when the object is deleted
type handlerChannels struct {
	updateChan        chan<- Notify
	receiveChan       chan CancelChannel
	currentCancelChan chan<- Notify
}

func makeDownloadHandler() *downloadHandler {
	return &downloadHandler{
		handlers: make(map[string]*handlerChannels),
	}
}

// Wrappers around createObject, modifyObject, and deleteObject

func (d *downloadHandler) modify(ctxArg interface{},
	key string, configArg interface{}) {

	log.Functionf("downloadHandler.modify(%s)", key)
	config := configArg.(types.DownloaderConfig)
	h, ok := d.handlers[config.Key()]
	if !ok {
		log.Fatalf("downloadHandler.modify called on config that does not exist")
	}
	select {
	case h.updateChan <- Notify{}:
		log.Functionf("downloadHandler.modify(%s) sent update", key)
	default:
		// handler is slow
		log.Warnf("downloadHandler.modify(%s) NOT sent update. Slow handler?", key)
	}
	// Cancel a download if client/user set RefCount = 0
	if h.currentCancelChan != nil && config.RefCount == 0 {
		select {
		case h.currentCancelChan <- Notify{}:
			log.Noticef("downloadHandler.modify(%s) sent cancel to %v",
				key, h.currentCancelChan)
		default:
			// handler is slow
			log.Warnf("downloadHandler.modify(%s) NOT sent cancel",
				key)
		}
		// We only cancel one operation once
		log.Noticef("downloadHandler.modify(%s) closing cancel channel %v",
			key, h.currentCancelChan)
		close(h.currentCancelChan)
		h.currentCancelChan = nil
	}
}

func (d *downloadHandler) create(ctxArg interface{},
	key string, configArg interface{}) {

	log.Functionf("downloadHandler.create(%s)", key)
	ctx := ctxArg.(*downloaderContext)
	config := configArg.(types.DownloaderConfig)
	_, ok := d.handlers[config.Key()]
	if ok {
		log.Fatalf("downloadHandler.create called on config that already exists")
	}
	updateChan := make(chan Notify, 1)
	receiveChan := make(chan CancelChannel, 1)
	h := handlerChannels{
		updateChan:  updateChan,
		receiveChan: receiveChan,
	}
	d.handlers[config.Key()] = &h

	// Pick up the current cancel channel from the receiveChan and save
	// it so it can be used if there is a cancel
	go func() {
		for ch := range receiveChan {
			if h.currentCancelChan != nil && ch != nil {
				log.Noticef("downloadHandler(%s) received updated cancelChan %v old %v",
					key, ch, h.currentCancelChan)
			}
			if ch != h.currentCancelChan {
				if h.currentCancelChan != nil {
					close(h.currentCancelChan)
				}
				h.currentCancelChan = ch
			}
		}
		if h.currentCancelChan != nil {
			log.Noticef("downloadHandler(%s) receiveChan func done", key)
		}
	}()

	log.Functionf("Creating %s at %s", "runHandler", agentlog.GetMyStack())
	go runHandler(ctx, key, updateChan, receiveChan)
	select {
	case h.updateChan <- Notify{}:
		log.Functionf("downloadHandler.create(%s) sent notify", key)
	default:
		// Shouldn't happen since we just created channel
		log.Fatalf("downloadHandler.create(%s) NOT sent notify", key)
	}
}

func (d *downloadHandler) delete(ctxArg interface{}, key string,
	configArg interface{}) {

	log.Functionf("downloadHandler.delete(%s)", key)
	// Do we have a channel/goroutine?
	h, ok := d.handlers[key]
	if !ok {
		log.Functionf("downloadHandler.delete: unknown %s", key)
		return
	}
	if h.currentCancelChan != nil {
		select {
		case h.currentCancelChan <- Notify{}:
			log.Noticef("downloadHandler.delete(%s) sent cancel to %v",
				key, h.currentCancelChan)
		default:
			// handler is slow
			log.Warnf("downloadHandler.delete(%s) NOT sent cancel. Slow handler?", key)
		}
		// We only cancel one operation once
		close(h.currentCancelChan)
		h.currentCancelChan = nil
	}
	log.Functionf("Closing update channel")
	close(h.updateChan)
	h.updateChan = nil

	log.Functionf("Closing receive channel")
	close(h.receiveChan)
	h.receiveChan = nil

	delete(d.handlers, key)
	log.Functionf("downloadHandler.delete(%s) done", key)
}
