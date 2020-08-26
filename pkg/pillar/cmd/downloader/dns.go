// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Handles both create and modify events
func handleDNSModify(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	status := statusArg.(types.DeviceNetworkStatus)
	if key != "global" {
		log.Infof("handleDNSModify: ignoring %s", key)
		return
	}
	log.Infof("handleDNSModify for %s", key)
	// Ignore test status and timestamps
	if ctx.deviceNetworkStatus.Equal(status) {
		log.Infof("handleDNSModify unchanged")
		return
	}
	ctx.deviceNetworkStatus = status
	log.Infof("handleDNSModify %d free management ports addresses; %d any",
		types.CountLocalAddrFreeNoLinkLocal(ctx.deviceNetworkStatus),
		types.CountLocalAddrAnyNoLinkLocal(ctx.deviceNetworkStatus))

	log.Infof("handleDNSModify done for %s", key)
}

func handleDNSDelete(ctxArg interface{}, key string, statusArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	log.Infof("handleDNSDelete for %s", key)
	if key != "global" {
		log.Infof("handleDNSDelete: ignoring %s", key)
		return
	}
	ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	log.Infof("handleDNSDelete done for %s", key)
}
