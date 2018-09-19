// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

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
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
)

// Context used for the underlaying pubsub subscription.
// this package
type context struct {
	Found bool
	C     <-chan string
	// Private info
	aa       *types.AssignableAdapters
	model    string
	sub      *pubsub.Subscription
}

func Subscribe(aa *types.AssignableAdapters, model string) *context {

	ctx := context{model: model, aa: aa}
	sub, err := pubsub.Subscribe("", types.AssignableAdapters{},
		false, &ctx)
	if err != nil {
		log.Fatal(err)
	}
	sub.ModifyHandler = handleAAModify
	sub.DeleteHandler = handleAADelete
	ctx.sub = sub
	ctx.C = sub.C
	sub.Activate()
	return &ctx
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
	*ctx.aa = config
	ctx.Found = true
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
	log.Infof("handleAADelete: found %s\n", ctx.model)
	ctx.Found = false
	ctx.aa = &types.AssignableAdapters{}
	log.Infof("handleAADelete done for %s\n", key)
}
