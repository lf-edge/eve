// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Handles both create and modify events
func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Infof("handleGlobalConfigModify: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigModify for %s", key)
	var gcp *types.ConfigItemValueMap
	debug, gcp = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	if gcp != nil {
		if gcp.GlobalValueInt(types.DownloadRetryTime) != 0 {
			retryTime = time.Duration(gcp.GlobalValueInt(types.DownloadRetryTime)) * time.Second
		}
		ctx.GCInitialized = true
	}
	log.Infof("handleGlobalConfigModify done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Infof("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Infof("handleGlobalConfigDelete for %s", key)
	debug, _ = agentlog.HandleGlobalConfig(ctx.subGlobalConfig, agentName,
		debugOverride)
	log.Infof("handleGlobalConfigDelete done for %s", key)
}
