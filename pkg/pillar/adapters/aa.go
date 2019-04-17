// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package to get initial (and updates) to AssignableAdapters for our model.
// Usage:
//	model := hardware.GetHardwareModel()
//	aa := types.AssignableAdapters{}
//      subAa := assignableadapters.Subscribe(&aa, model)
// Then in select loop:
//	case change := <-subAa.C:
//		subAa.ProcessChange(change)
//
// The aa is updated initially and when there is a change. On delete it
// is set to its default value. aa.Found is set when the model has been found.

package adapters

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/eve/pkg/pillar/cast"
	"github.com/zededa/eve/pkg/pillar/pubsub"
	"github.com/zededa/eve/pkg/pillar/types"
)

type ModifyHandler func(userCtx interface{}, config types.AssignableAdapters,
	status *types.AssignableAdapters)
type DeleteHandler func(userCtx interface{}, status *types.AssignableAdapters)

// Context used for the underlaying pubsub subscription.
// this package
type context struct {
	C <-chan string
	// Private info
	aa            *types.AssignableAdapters
	model         string
	sub           *pubsub.Subscription
	modifyHandler *ModifyHandler
	deleteHandler *DeleteHandler
	userCtx       interface{}
}

func Subscribe(aa *types.AssignableAdapters, model string,
	modifyHandler *ModifyHandler, deleteHandler *DeleteHandler,
	userCtx interface{}) *context {

	ctx := context{model: model, aa: aa}
	sub, err := pubsub.Subscribe("", types.AssignableAdapters{},
		false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	sub.ModifyHandler = handleAAModify
	sub.DeleteHandler = handleAADelete
	ctx.modifyHandler = modifyHandler
	ctx.deleteHandler = deleteHandler
	ctx.userCtx = userCtx
	ctx.sub = sub
	ctx.C = sub.C
	return &ctx
}

func (ctx *context) Activate() {
	ctx.sub.Activate()
}

func (ctx *context) ProcessChange(change string) {
	ctx.sub.ProcessChange(change)
}

func handleAAModify(ctxArg interface{}, key string, configArg interface{}) {
	config := cast.CastAssignableAdapters(configArg)
	ctx := ctxArg.(*context)
	// Only care about my model
	if key != ctx.model {
		log.Debugf("handleAAModify: ignoring %s, expecting %s\n",
			key, ctx.model)
		return
	}
	log.Infof("handleAAModify found %s\n", key)
	if ctx.modifyHandler != nil {
		(*ctx.modifyHandler)(ctx.userCtx, config, ctx.aa)
	} else {
		*ctx.aa = config
	}
	ctx.aa.Initialized = true
	log.Infof("handleAAModify done for %s\n", key)
}

func handleAADelete(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*context)
	// Only care about my model
	if key != ctx.model {
		log.Debugf("handleAADelete: ignoring %s, expecting %s\n",
			key, ctx.model)
		return
	}
	log.Infof("handleAADelete: found model %s\n", ctx.model)
	if ctx.deleteHandler != nil {
		(*ctx.deleteHandler)(ctx.userCtx, ctx.aa)
	} else {
		ctx.aa = &types.AssignableAdapters{}
	}
	ctx.aa.Initialized = false
	log.Infof("handleAADelete done for %s\n", key)
}
