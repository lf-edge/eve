// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of AppNetworkConfig structs
// from zedmanager and zedagent. Publish the status as AppNetworkStatus.
// Produce the updated configlets (for radvd, dnsmasq, ip*tables, lisp.config,
// ipset, ip link/addr/route configuration) based on that and apply those
// configlets.

package zedrouter

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	apitypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// DOCKERAPIPORT - constant define of docker API TCP port value
const DOCKERAPIPORT int = 2375

// DOCKERAPIVERSION - docker API version used
const DOCKERAPIVERSION string = "1.40"

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
func appStatsAndLogCollect(ctx *zedrouterContext) {
	log.Infof("appStatsAndLogCollect: containerStats, started")
	lastLogTime := make(map[string]string)
	appStatsCollectTimer := time.NewTimer(time.Duration(ctx.appStatsInterval) * time.Second)
	for {
		select {
		case <-appStatsCollectTimer.C:
			items, stopped := checkAppStopStatsCollect(ctx)
			if stopped {
				return
			}

			collectTime := time.Now() // all apps collection assign the same timestamp
			log.Infof("appStatsAndLogCollect: containerStats, timer loop")
			for _, st := range items {
				status := st.(types.AppNetworkStatus)
				if status.GetStatsIPAddr != nil {
					acMetrics, err := appContainerGetStats(status.GetStatsIPAddr)
					if err != nil {
						log.Errorf("appStatsAndLogCollect: can't get App %s Container Metrics on %s, %v",
							status.UUIDandVersion.UUID.String(), status.GetStatsIPAddr.String(), err)
						continue
					}
					acMetrics.UUIDandVersion = status.UUIDandVersion
					acMetrics.CollectTime = collectTime
					ctx.pubAppContainerMetrics.Publish(acMetrics.Key(), acMetrics)
					getAppContainerLogs(status, lastLogTime)
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
		go appStatsAndLogCollect(ctx)
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

func getAppContainerLogs(status types.AppNetworkStatus, last map[string]string) {
	var buf bytes.Buffer
	cli, containers, err := getAppContainers(status)
	if err != nil {
		return
	}

	for _, container := range containers {
		var lasttime, newtime, message string
		containerName := strings.Trim(container.Names[0], "/")
		if lt, ok := last[containerName]; ok {
			lasttime = lt
		}
		out, err := cli.ContainerLogs(context.Background(), container.ID, apitypes.ContainerLogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Timestamps: true,
			Since:      lasttime,
		})
		if err != nil {
			log.Errorf("getAppContainerLogs: log output error %v", err)
			continue
		}

		stdcopy.StdCopy(&buf, &buf, io.LimitReader(out, 100000))
		logLines := strings.Split(buf.String(), "\n")
		log.Debugf("getAppContainerLogs: container %s, lasttime %s, lines %d", containerName, lasttime, len(logLines))
		for _, line := range logLines {
			sline := strings.SplitN(line, " ", 2)
			time := sline[0]
			if time == lasttime {
				log.Debugf("getAppContainerLogs: time same %s, skip", time)
				continue
			}
			if len(time) > 0 && len(sline) == 2 {
				newtime = time
				// some message has timestamp like: [\u003c6\u003e 2020-06-23 22:29:01.871 +00:00 [INF] - ]
				// remove the timestamp in message if any since we always have timestamp
				msg := strings.SplitN(sline[1], " +00:00 [", 2)
				if len(msg) > 1 {
					message = " [" + msg[1]
				} else {
					message = msg[0]
				}
				// insert container-name, app-UUID and module timestamp in log to be processed by logmanager
				log.WithFields(log.Fields{
					"appuuid":       status.UUIDandVersion.UUID.String(),
					"containername": containerName,
					"eventtime":     time,
				}).Infof("%s", message)
			}
		}
		// remember the last entry time by a container
		if newtime != "" {
			last[containerName] = newtime
		}
	}

	// cleanup saved timestamp if container is removed
	for key := range last {
		var found bool
		for _, container := range containers {
			containerName := strings.Trim(container.Names[0], "/")
			if key == containerName {
				found = true
				break
			}
		}
		if !found {
			delete(last, key)
		}
	}
}

func getAppContainers(status types.AppNetworkStatus) (*client.Client, []apitypes.Container, error) {
	containerEndpoint := "tcp://" + status.GetStatsIPAddr.String() + ":" + strconv.Itoa(DOCKERAPIPORT)
	cli, err := client.NewClient(containerEndpoint, DOCKERAPIVERSION, nil, nil)
	if err != nil {
		log.Errorf("getAppContainers: client create failed, error %v", err)
		return nil, nil, err
	}

	containers, err := cli.ContainerList(context.Background(), apitypes.ContainerListOptions{})
	if err != nil {
		log.Errorf("getAppContainers: Container list error %v", err)
		return nil, nil, err
	}

	return cli, containers, nil
}
