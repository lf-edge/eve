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
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// DOCKERAPIPORT - constant define of docker API TCP port value
const DOCKERAPIPORT int = 2375

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

func appConfigContainerStatsACL(appIPAddr net.IP, isRemove bool) {
	var action string
	if isRemove {
		action = "-D"
	} else {
		action = "-A"
	}
	// install or remove the App Container Stats blocking ACL
	// This ACL blocks the other Apps accessing through the same subnet to 'appIPAddr:DOCKERAPIPORT'
	// in TCP protocol, and only allow the Dom0 process to query the App's docker stats
	// - this blocking is only possible in the 'raw' table and 'PREROUTING' chain due to the marking
	//   is done in the 'mangle' of 'PREROUTING'
	// - this blocking ACL does not block the Dom0 access to the above TCP endpoint on the same
	//   subnet. This is due to the IP packets from Dom0 to the internal bridge entering the linux
	//   forwarding through the 'OUTPUT' chain
	// - this blocking does not seem to work if further matching to the '--physdev', so the drop action
	//   needs to be at network layer3
	// - XXX currently the 'drop' mark of 0xffffff on the flow of internal traffic on bridge does not work,
	//   later it may be possible to change below '-j DROP' to '-j MARK' action
	err := iptables.IptableCmd("-t", "raw", action, "PREROUTING", "-d", appIPAddr.String(), "-p", "tcp",
		"--dport", strconv.Itoa(DOCKERAPIPORT), "-j", "DROP")
	if err != nil {
		log.Errorf("appCheckContainerStatsACL: iptableCmd err %v", err)
	} else {
		log.Infof("appCheckContainerStatsACL: iptableCmd %s for %s", action, appIPAddr.String())
	}
}
