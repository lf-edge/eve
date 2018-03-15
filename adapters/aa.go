// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Package to get initial (and updates) to AssignableAdapters for our model.
// Usage:
//	model := hardware.GetHardwareModel()
//	aa := types.AssignableAdapters{}
//      changes, func, ctx := assignableadapters.Init(&aa, model)
// Then in select loop:
//       event := changes { func(&ctx, event) }
// The aa is updated initially and when there is a change. On delete it
// is set to its default value.

package adapters

import (
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"log"
)

// Context which is passed from Init to processEventFn by the user of
// this package
type context struct {
	aa    *types.AssignableAdapters
	model string
	Found bool
}

type processEventFn func(ctx *context, event string)

const dirName = "/var/tmp/zededa/AssignableAdapters"

func Init(aa *types.AssignableAdapters, model string) (chan string, processEventFn, context) {
	ctx := context{model: model, aa: aa}
	// Call go watch/subscribe
	changes := make(chan string)
	go watch.WatchStatus(dirName, changes)

	return changes, processEvent, ctx
}

func processEvent(ctx *context, event string) {
	watch.HandleStatusEvent(event, ctx, dirName,
		&types.AssignableAdapters{},
		handleAAModify, handleAADelete, nil)
}

func handleAAModify(ctxArg interface{}, key string, configArg interface{}) {
	config := configArg.(*types.AssignableAdapters)
	ctx := ctxArg.(*context)
	// Only care about my model
	if key != ctx.model {
		log.Printf("handleAAModify: ignoring %s, expecting %s\n",
			key, ctx.model)
		return
	}
	log.Printf("handleAAModify found %s\n", key)
	*ctx.aa = *config
	ctx.Found = true
	log.Printf("handleAAModify done for %s\n", key)
}

func handleAADelete(ctxArg interface{}, key string) {
	log.Printf("handleAADelete for %s\n", key)
	ctx := ctxArg.(*context)
	// Only care about my model
	if key != ctx.model {
		log.Printf("handleAADelete: ignoring %s, expecting %s\n",
			key, ctx.model)
		return
	}
	log.Printf("handleAADelete: found %s\n", ctx.model)
	ctx.Found = false
	ctx.aa = &types.AssignableAdapters{}
	log.Printf("handleAADelete done for %s\n", key)
}
