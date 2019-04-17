// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/pubsub"
)

func downloaderSubscription(ctx *zedagentContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case baseOsObj:
		sub = ctx.subBaseOsDownloadStatus
	case certObj:
		sub = ctx.subCertObjDownloadStatus
	case appImgObj:
		sub = ctx.subAppImgDownloadStatus
	default:
		log.Fatalf("downloaderSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func downloaderGetAll(ctx *zedagentContext) map[string]interface{} {
	sub1 := downloaderSubscription(ctx, baseOsObj)
	items1 := sub1.GetAll()
	sub2 := downloaderSubscription(ctx, certObj)
	items2 := sub2.GetAll()
	sub3 := downloaderSubscription(ctx, appImgObj)
	items3 := sub3.GetAll()

	items := make(map[string]interface{})
	for k, i := range items1 {
		items[k] = i
	}
	for k, i := range items2 {
		items[k] = i
	}
	for k, i := range items3 {
		items[k] = i
	}
	return items
}
