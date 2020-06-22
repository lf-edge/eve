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

// DOCKERAPIPORT - constant define of docker API TCP port value
const DOCKERAPIPORT int = 2375

// check if we need to launch the goroutine to collect App container stats
func appCheckStatsCollect(ctx *zedrouterContext, config *types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	oldIPAddr := status.GetStatsIPAddr
	if config != nil {
		status.GetStatsIPAddr = config.GetStatsIPAddr
	} else {
		status.GetStatsIPAddr = nil
	}
	publishAppNetworkStatus(ctx, status)
	if status.GetStatsIPAddr == nil && oldIPAddr != nil ||
		status.GetStatsIPAddr != nil && !status.GetStatsIPAddr.Equal(oldIPAddr) {
		log.Infof("appCheckStatsCollect: config ip %v, status ip %v", status.GetStatsIPAddr, oldIPAddr)
		if oldIPAddr == nil && status.GetStatsIPAddr != nil {
			ensureStatsCollectRunning(ctx)
		}
		appChangeContainerStatsACL(status.GetStatsIPAddr, oldIPAddr)
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

func appChangeContainerStatsACL(newIPAddr, oldIPAddr net.IP) {
	if oldIPAddr != nil {
		// remove the previous installed blocking ACL
		appConfigContainerStatsACL(oldIPAddr, true)
	}
	if newIPAddr != nil {
		// install the App Container blocking ACL
		appConfigContainerStatsACL(newIPAddr, false)
	}
}

// reinstall the App Container blocking ACL to place in the top
func appStatsMayNeedReinstallACL(ctx *zedrouterContext, config types.AppNetworkConfig) {
	sub := ctx.subAppNetworkConfig
	items := sub.GetAll()
	for _, item := range items {
		cfg := item.(types.AppNetworkConfig)
		if cfg.Key() == config.Key() {
			log.Infof("appStatsMayNeedReinstallACL: same app, skip")
			continue
		}
		if cfg.GetStatsIPAddr != nil {
			appConfigContainerStatsACL(cfg.GetStatsIPAddr, true)
			appConfigContainerStatsACL(cfg.GetStatsIPAddr, false)
			log.Infof("appStatsMayNeedReinstallACL: reinstall %s\n", cfg.GetStatsIPAddr.String())
		}
	}
}
