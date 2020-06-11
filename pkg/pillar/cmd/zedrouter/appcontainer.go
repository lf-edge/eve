// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of AppNetworkConfig structs
// from zedmanager and zedagent. Publish the status as AppNetworkStatus.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables, lisp.config,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"net"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// check if we need to launch the goroutine to collect App container stats
func appCheckStatsCollect(ctx *zedrouterContext, config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	oldIPAddr := status.GetStatsIPAddr
	status.GetStatsIPAddr = config.GetStatsIPAddr
	publishAppNetworkStatus(ctx, status)
	if !config.GetStatsIPAddr.Equal(oldIPAddr) {
		log.Infof("appCheckStatsCollect: config ip %s, status ip %s", config.GetStatsIPAddr.String(), oldIPAddr.String())
		if oldIPAddr == nil && config.GetStatsIPAddr != nil {
			ensureStatsCollectRunning(ctx)
		}
	}
}

// goroutine for App container stats collection
func appStatsCollect(ctx *zedrouterContext) {
	log.Infof("appStatsCollect: containerStats, started")
	appStatsCollectTimer := time.NewTimer(time.Duration(ctx.appStatsInterval) * time.Second)
	for {
		select {
		case <-appStatsCollectTimer.C:
			items, stopped := checkAppStopStatsCollect(ctx)
			if stopped {
				return
			}

			collectTime := time.Now() // all apps collection assign the same timestamp
			for _, st := range items {
				status := st.(types.AppNetworkStatus)
				if status.GetStatsIPAddr != nil {
					acMetrics, err := appContainerGetStats(status.GetStatsIPAddr)
					if err != nil {
						log.Errorf("appStatsCollect: can't get App %s Container Metrics on %s, %v",
							status.UUIDandVersion.UUID.String(), status.GetStatsIPAddr.String(), err)
						continue
					}
					acMetrics.UUIDandVersion = status.UUIDandVersion
					acMetrics.CollectTime = collectTime
					ctx.pubAppContainerMetrics.Publish(acMetrics.Key(), acMetrics)
				}
			}
			appStatsCollectTimer = time.NewTimer(time.Duration(ctx.appStatsInterval) * time.Second)
		}
	}
}

func ensureStatsCollectRunning(ctx *zedrouterContext) {
	ctx.appStatsMutex.Lock()
	if !ctx.appCollectStatsRunning {
		ctx.appCollectStatsRunning = true
		ctx.appStatsMutex.Unlock()
		go appStatsCollect(ctx)
	} else {
		ctx.appStatsMutex.Unlock()
	}
}

func checkAppStopStatsCollect(ctx *zedrouterContext) (map[string]interface{}, bool) {
	var numStatsIP int
	ctx.appStatsMutex.Lock()
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		if status.GetStatsIPAddr != nil {
			numStatsIP++
		}
	}
	if numStatsIP == 0 {
		log.Infof("checkAppStopStatsCollect: no stats IP anymore. stop and exit out")
		ctx.appCollectStatsRunning = false
		ctx.appStatsMutex.Unlock()
		return items, true
	}
	ctx.appStatsMutex.Unlock()
	return items, false
}

func appContainerGetStats(ipAddr net.IP) (types.AppContainerMetrics, error) {
	var acMetrics types.AppContainerMetrics
	// XXX collect container stats for each container with the docker API endpoint ipAddr
	return acMetrics, nil
}
