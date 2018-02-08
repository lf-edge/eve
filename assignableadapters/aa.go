// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Package to get initial (and updates) to AssignableDevices for our model.
// Usage:
//       changes, func, ctx := assignabledevices.Init(aa, model)
// Then in select loop:
//       event := changes { func(&ctx, event) }
// The aa is updated initially and when there is a change. On delete it
// is set to its default value.

package assignabledevices

import (
	"fmt"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/watch"
	"log"
)

// Context which is passed from Init to processEventFn by the user of
// this package
type context struct {
	aa    *types.AssignableAdapters
	model string
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
		fmt.Printf("handleAAModify: ignoring %s\n", key)
		return
	}
	log.Printf("handleAAModify for %s\n", key)
	*ctx.aa = *config
	log.Printf("handleAAModify done for %s\n", key)
}

func handleAADelete(ctxArg interface{}, key string) {
	log.Printf("handleAADelete for %s\n", key)
	ctx := ctxArg.(*context)
	// Only care about my model
	if key != ctx.model {
		fmt.Printf("handleAADelete: ignoring %s\n", key)
		return
	}
	ctx.aa = &types.AssignableAdapters{}
	log.Printf("handleAADelete done for %s\n", key)
}
