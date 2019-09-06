// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func verifierSubscription(ctx *zedagentContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case types.BaseOsObj:
		sub = ctx.subBaseOsVerifierStatus
	case types.AppImgObj:
		sub = ctx.subAppImgVerifierStatus
	default:
		log.Fatalf("verifierSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func verifierGetAll(ctx *zedagentContext) map[string]interface{} {
	sub1 := verifierSubscription(ctx, types.BaseOsObj)
	items1 := sub1.GetAll()
	sub2 := verifierSubscription(ctx, types.AppImgObj)
	items2 := sub2.GetAll()

	items := make(map[string]interface{})
	for k, i := range items1 {
		items[k] = i
	}
	for k, i := range items2 {
		items[k] = i
	}
	return items
}
