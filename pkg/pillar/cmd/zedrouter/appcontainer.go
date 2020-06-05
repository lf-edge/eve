// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of AppNetworkConfig structs
// from zedmanager and zedagent. Publish the status as AppNetworkStatus.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables, lisp.config,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// check if we need to launch the goroutine to collect App container stats
func appCheckStatsCollect(ctx *zedrouterContext, config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	oldIPAddr := status.GetStatsIPAddr
	status.GetStatsIPAddr = config.GetStatsIPAddr
	if strings.Compare(config.GetStatsIPAddr, oldIPAddr) != 0 {
		log.Infof("appCheckStatsCollect: config ip %s, status ip %s", config.GetStatsIPAddr, oldIPAddr)
		if oldIPAddr == "" && config.GetStatsIPAddr != "" {
			ctx.appStatsMutex.Lock()
			publishAppNetworkStatus(ctx, status)
			if !ctx.appCollectStatsRunning {
				ctx.appStatsMutex.Unlock()
				go appStatsCollect(ctx)
			} else {
				ctx.appStatsMutex.Unlock()
			}
		}
	}
}

// goroutine for App container stats collection
func appStatsCollect(ctx *zedrouterContext) {
	log.Infof("appStatsCollect: containerStats, started")
	appStatsCollectTimer := time.NewTimer(600 * time.Second)
	for {
		select {
		case <-appStatsCollectTimer.C:
			var numStatsIP int
			ctx.appStatsMutex.Lock()
			pub := ctx.pubAppNetworkStatus
			items := pub.GetAll()
			for _, st := range items {
				status := st.(types.AppNetworkStatus)
				if status.GetStatsIPAddr != "" {
					numStatsIP++
				}
			}
			if numStatsIP == 0 {
				log.Infof("appStatsCollect: no stats IP anymore. stop and exit out")
				ctx.appCollectStatsRunning = false
				ctx.appStatsMutex.Unlock()
				return
			}
			ctx.appStatsMutex.Unlock()
			for _, st := range items {
				status := st.(types.AppNetworkStatus)
				if status.GetStatsIPAddr != "" {
					// XXX temp for later, collection function to fill in here
				}
			}
			appStatsCollectTimer = time.NewTimer(600 * time.Second)
		}
	}
}
