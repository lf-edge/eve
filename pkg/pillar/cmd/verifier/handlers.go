// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// Notify simple struct to pass notification messages
type Notify struct{}

type verifyHandler struct {
	// We have one goroutine per provisioned domU object.
	// Channel is used to send notifications about config (add and updates)
	// Channel is closed when the object is deleted
	// The go-routine owns writing status for the object
	// The key in the map is the objects Key()

	handlers map[string]chan<- Notify
}

func makeVerifyHandler() *verifyHandler {
	return &verifyHandler{
		handlers: make(map[string]chan<- Notify),
	}
}

// Wrappers around handleCreate, handleModify, and handleDelete

// Determine whether it is an create or modify
func (v *verifyHandler) modify(ctxArg interface{},
	key string, configArg interface{}, oldConfigArg interface{}) {

	typeName := pubsub.TypeToName(configArg)
	handlerKey := fmt.Sprintf("%s+%s", typeName, key)
	log.Functionf("verifyHandler.modify(%s)", handlerKey)
	h, ok := v.handlers[handlerKey]
	if !ok {
		log.Fatalf("verifyHandler.modify called on config that does not exist")
	}
	select {
	case h <- Notify{}:
		log.Functionf("verifyHandler.modify(%s) sent notify", handlerKey)
	default:
		// handler is slow
		log.Warnf("verifyHandler.modify(%s) NOT sent notify. Slow handler?", handlerKey)
	}
	log.Functionf("verifyHandler.modify(%s) done", handlerKey)
}

func (v *verifyHandler) create(ctxArg interface{},
	key string, configArg interface{}) {

	typeName := pubsub.TypeToName(configArg)
	handlerKey := fmt.Sprintf("%s+%s", typeName, key)
	log.Functionf("verifyHandler.create(%s)", handlerKey)
	ctx := ctxArg.(*verifierContext)
	h, ok := v.handlers[handlerKey]
	if ok {
		log.Fatalf("verifyHandler.create called on config that already exists")
	}
	h1 := make(chan Notify, 1)
	v.handlers[handlerKey] = h1
	switch typeName {
	case "VerifyImageConfig":
		log.Functionf("Creating %s at %s", "runHandler",
			agentlog.GetMyStack())
		go runHandler(ctx, key, h1)
	default:
		log.Fatalf("Unknown type %s", typeName)
	}
	h = h1
	select {
	case h <- Notify{}:
		log.Functionf("verifyHandler.create(%s) sent notify", handlerKey)
	default:
		// Shouldn't happen since we just created channel
		log.Fatalf("verifyHandler.create(%s) NOT sent notify", handlerKey)
	}
	log.Functionf("verifyHandler.create(%s) done", handlerKey)
}

func (v *verifyHandler) delete(ctxArg interface{}, key string,
	configArg interface{}) {

	typeName := pubsub.TypeToName(configArg)
	handlerKey := fmt.Sprintf("%s+%s", typeName, key)
	log.Functionf("verifyHandler.delete(%s)", handlerKey)
	// Do we have a channel/goroutine?
	h, ok := v.handlers[handlerKey]
	if ok {
		log.Tracef("Closing channel")
		close(h)
		delete(v.handlers, handlerKey)
	} else {
		log.Tracef("verifyHandler.delete: unknown %s", handlerKey)
		return
	}
	log.Functionf("verifyHandler.delete(%s) done", handlerKey)
}
