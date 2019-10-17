// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func downloaderSubscription(ctx *zedagentContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case types.BaseOsObj:
		sub = ctx.subBaseOsDownloadStatus
	case types.CertObj:
		sub = ctx.subCertObjDownloadStatus
	case types.AppImgObj:
		sub = ctx.subAppImgDownloadStatus
	default:
		log.Fatalf("downloaderSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func downloaderGetAll(ctx *zedagentContext) map[string]interface{} {
	sub1 := downloaderSubscription(ctx, types.BaseOsObj)
	items1 := sub1.GetAll()
	sub2 := downloaderSubscription(ctx, types.CertObj)
	items2 := sub2.GetAll()
	sub3 := downloaderSubscription(ctx, types.AppImgObj)
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
