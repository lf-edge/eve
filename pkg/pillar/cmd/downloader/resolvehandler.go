// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	log "github.com/sirupsen/logrus"
)

type resolveHandler struct {
	// We have one goroutine per provisioned domU object.
	// Channel is used to send notifications about config (add and updates)
	// Channel is closed when the object is deleted
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key().

	handlers map[string]chan<- Notify
}

func makeResolveHandler() *resolveHandler {
	return &resolveHandler{
		handlers: make(map[string]chan<- Notify),
	}
}

// Wrappers around modifyObject, and deleteObject

func (r *resolveHandler) modify(ctxArg interface{},
	key string, configArg interface{}, isContentTree bool) {

	log.Infof("resolveHandler.modify(%s) and isContentTree(%v)", key, isContentTree)
	ctx := ctxArg.(*downloaderContext)
	h, ok := r.handlers[key]
	if !ok {
		h1 := make(chan Notify, 1)
		r.handlers[key] = h1
		go runResolveHandler(ctx, key, isContentTree, h1)
		h = h1
	}
	select {
	case h <- Notify{}:
		log.Infof("resolveHandler.modify(%s) sent notify", key)
	default:
		// handler is slow
		log.Warnf("resolveHandler.modify(%s) NOT sent notify. Slow handler?", key)
	}
}

func (r *resolveHandler) delete(ctxArg interface{},
	key string, configArg interface{}, isContentTree bool) {

	log.Infof("resolveHandler.delete(%s) and isContentTree(%v)", key, isContentTree)
	// Do we have a channel/goroutine?
	h, ok := r.handlers[key]
	if ok {
		log.Debugf("Closing channel")
		close(h)
		delete(r.handlers, key)
	} else {
		log.Debugf("resolveHandler.delete: unknown %s", key)
		return
	}
	log.Infof("resolveHandler.delete(%s) done", key)
}
