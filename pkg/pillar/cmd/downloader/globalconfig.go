// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		if gcp.GlobalValueInt(types.DownloadRetryTime) != 0 {
			retryTime = time.Duration(gcp.GlobalValueInt(types.DownloadRetryTime)) * time.Second
		}
		if gcp.GlobalValueInt(types.DownloadStalledTime) != 0 {
			maxStalledTime = time.Duration(gcp.GlobalValueInt(types.DownloadStalledTime)) * time.Second
		}
		ctx.downloadMaxPortCost = uint8(gcp.GlobalValueInt(types.DownloadMaxPortCost))
		ctx.globalConfig = *gcp
		ctx.GCInitialized = true
		reinitNetdumper(ctx)
	}
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	ctx.globalConfig = *types.DefaultConfigItemValueMap()
	reinitNetdumper(ctx)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func reinitNetdumper(ctx *downloaderContext) {
	gcp := ctx.globalConfig
	netDumper := ctx.netDumper
	netdumpEnabled := gcp.GlobalValueBool(types.NetDumpEnable)
	if netdumpEnabled {
		if netDumper == nil {
			netDumper = &netdump.NetDumper{}
		}
		maxCount := gcp.GlobalValueInt(types.NetDumpTopicMaxCount)
		netDumper.MaxDumpsPerTopic = int(maxCount)
	} else {
		netDumper = nil
	}
	ctx.netdumpWithPCAP = gcp.GlobalValueBool(types.NetDumpDownloaderPCAP)
	ctx.netdumpWithHdrFieldVal = gcp.GlobalValueBool(
		types.NetDumpDownloaderHTTPWithFieldValue)
	ctx.netDumper = netDumper
}
