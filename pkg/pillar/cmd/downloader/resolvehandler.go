// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

type resolveHandler struct {
	// We have one goroutine per provisioned domU object.
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key().

	handlers map[string]*handlerChannels
}

func makeResolveHandler() *resolveHandler {
	return &resolveHandler{
		handlers: make(map[string]*handlerChannels),
	}
}

// Wrappers around modifyObject, and deleteObject

func (r *resolveHandler) create(ctxArg interface{},
	key string, configArg interface{}) {

	log.Functionf("resolveHandler.modify(%s)", key)
	ctx := ctxArg.(*downloaderContext)
	_, ok := r.handlers[key]
	if ok {
		log.Fatalf("resolveHandler.create called on config that already exists")
	}
	updateChan := make(chan Notify, 1)
	receiveChan := make(chan CancelChannel, 1)
	h := handlerChannels{
		updateChan:  updateChan,
		receiveChan: receiveChan,
	}
	r.handlers[key] = &h

	// Pick up the current cancel channel from the receiveChan and save
	// it so it can be used if there is a cancel
	go func() {
		for ch := range receiveChan {
			if h.currentCancelChan != nil && ch != nil {
				log.Noticef("resolveHandler(%s) received updated cancelChan %v",
					key, ch)
			}
			if h.currentCancelChan != nil {
				close(h.currentCancelChan)
			}
			h.currentCancelChan = ch
		}
		if h.currentCancelChan != nil {
			log.Noticef("resolveHandler(%s) receiveChan func done", key)
		}
	}()

	log.Functionf("Creating %s at %s", "runResolveHandler",
		agentlog.GetMyStack())
	go runResolveHandler(ctx, key, updateChan, receiveChan)

	select {
	case h.updateChan <- Notify{}:
		log.Functionf("resolveHandler.modify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("resolveHandler.modify(%s) NOT sent notify. Slow handler?", key)
	}
}

func (r *resolveHandler) modify(ctxArg interface{},
	key string, configArg interface{}, oldConfigArg interface{}) {

	log.Functionf("resolveHandler.modify(%s)", key)
	h, ok := r.handlers[key]
	if !ok {
		log.Fatalf("resolveHandler.modify called on config that does not exist")
	}
	select {
	case h.updateChan <- Notify{}:
		log.Functionf("resolveHandler.modify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("resolveHandler.modify(%s) NOT sent notify. Slow handler?", key)
	}
}

func (r *resolveHandler) delete(ctxArg interface{},
	key string, configArg interface{}) {

	log.Functionf("resolveHandler.delete(%s)", key)
	// Do we have a channel/goroutine?
	h, ok := r.handlers[key]
	if !ok {
		log.Functionf("resolveHandler.delete: unknown %s", key)
		return
	}

	if h.currentCancelChan != nil {
		select {
		case h.currentCancelChan <- Notify{}:
			log.Noticef("resolveHandler.delete(%s) sent cancel to %v",
				key, h.currentCancelChan)
		default:
			// handler is slow
			log.Warnf("resolveHandler.delete(%s) NOT sent cancel",
				key)
		}
		// We only cancel one operation once
		log.Noticef("resolveHandler.modify(%s) closing cancel channel %v",
			key, h.currentCancelChan)
		close(h.currentCancelChan)
		h.currentCancelChan = nil
	}
	log.Functionf("Closing update channel")
	close(h.updateChan)
	h.updateChan = nil

	log.Functionf("Closing receive channel")
	close(h.receiveChan)
	h.receiveChan = nil

	delete(r.handlers, key)
	log.Functionf("resolveHandler.delete(%s) done", key)
}
