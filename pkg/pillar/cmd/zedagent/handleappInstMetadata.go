/*
 * Copyright (c) 2021. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zedagent

import (
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleAppInstMetaDataCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppInstMetaDataImpl(ctxArg, key, statusArg)
}

func handleAppInstMetaDataModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppInstMetaDataImpl(ctxArg, key, statusArg)
}

func handleAppInstMetaDataDelete(ctxArg interface{}, key string, statusArg interface{}) {
	appInstMetaData := statusArg.(types.AppInstMetaData)
	ctx := ctxArg.(*zedagentContext)
	triggerPublishDeletedObjectInfo(
		ctx, info.ZInfoTypes_ZiAppInstMetaData, key, appInstMetaData)
}

func handleAppInstMetaDataImpl(ctxArg interface{}, key string, statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	triggerPublishObjectInfo(ctx, info.ZInfoTypes_ZiAppInstMetaData, key)
}
