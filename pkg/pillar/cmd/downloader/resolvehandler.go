// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
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

func (r *resolveHandler) create(ctxArg interface{},
	key string, configArg interface{}) {

	log.Functionf("resolveHandler.modify(%s)", key)
	ctx := ctxArg.(*downloaderContext)
	h, ok := r.handlers[key]
	if ok {
		log.Fatalf("resolveHandler.create called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	r.handlers[key] = h1
	log.Functionf("Creating %s at %s", "runResolveHandler",
		agentlog.GetMyStack())
	go runResolveHandler(ctx, key, h1)
	h = h1

	select {
	case h <- Notify{}:
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
	case h <- Notify{}:
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
	if ok {
		log.Tracef("Closing channel")
		close(h)
		delete(r.handlers, key)
	} else {
		log.Tracef("resolveHandler.delete: unknown %s", key)
		return
	}
	log.Functionf("resolveHandler.delete(%s) done", key)
}
