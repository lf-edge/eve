// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/eve/pkg/pillar/pubsub"
)

func verifierSubscription(ctx *zedagentContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case baseOsObj:
		sub = ctx.subBaseOsVerifierStatus
	case appImgObj:
		sub = ctx.subAppImgVerifierStatus
	default:
		log.Fatalf("verifierSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func verifierGetAll(ctx *zedagentContext) map[string]interface{} {
	sub1 := verifierSubscription(ctx, baseOsObj)
	items1 := sub1.GetAll()
	sub2 := verifierSubscription(ctx, appImgObj)
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
