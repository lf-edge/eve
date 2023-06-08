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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	apitypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/sirupsen/logrus"
)

// DOCKERAPIPORT - constant define of docker API TCP port value
const DOCKERAPIPORT int = 2375

// DOCKERAPIVERSION - docker API version used
const DOCKERAPIVERSION string = "1.40"

// convert from nanoSeconds to Seconds
const nanoSecToSec uint64 = 1000000000

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
		log.Functionf("appCheckStatsCollect: config ip %v, status ip %v", status.GetStatsIPAddr, oldIPAddr)
		if oldIPAddr == nil && status.GetStatsIPAddr != nil {
			ensureStatsCollectRunning(ctx)
		}
		appChangeContainerStatsACL(status.GetStatsIPAddr, oldIPAddr)
	}
}

// goroutine for App container stats collection
func appStatsAndLogCollect(ctx *zedrouterContext) {
	log.Functionf("appStatsAndLogCollect: containerStats, started")
	// cache the container last timestamp of log entries of the batch
	lastLogTime := make(map[string]time.Time)
	appStatsCollectTimer := time.NewTimer(time.Duration(ctx.appStatsInterval) * time.Second)
	for {
		select {
		case <-appStatsCollectTimer.C:
			items, stopped := checkAppStopStatsCollect(ctx)
			if stopped {
				return
			}

			var acNum, numlogs int
			collectTime := time.Now() // all apps collection assign the same timestamp
			for _, st := range items {
				status := st.(types.AppNetworkStatus)
				if status.GetStatsIPAddr != nil {
					// get a list of containers and client handle
					cli, containers, err := getAppContainers(status)
					if err != nil {
						log.Errorf("appStatsAndLogCollect: can't get App Containers %s on %s, %v",
							status.UUIDandVersion.UUID.String(), status.GetStatsIPAddr.String(), err)
						continue
					}
					acNum += len(containers)

					// collect container stats, and publish to zedclient
					acMetrics := getAppContainerStats(status, cli, containers)
					if len(acMetrics.StatsList) > 0 {
						acMetrics.UUIDandVersion = status.UUIDandVersion
						acMetrics.CollectTime = collectTime
						ctx.pubAppContainerMetrics.Publish(acMetrics.Key(), acMetrics)
					}

					// collect container logs and send through the logging system
					numlogs += getAppContainerLogs(ctx, status, lastLogTime, cli, containers)
				}
			}
			// log output every 5 min, see this goroutine running status and number of containers from App
			log.Functionf("appStatsAndLogCollect: containerStats, %d processed. total log entries %d, reset timer", acNum, numlogs)

			appStatsCollectTimer = time.NewTimer(time.Duration(ctx.appStatsInterval) * time.Second)
		}
	}
}

func ensureStatsCollectRunning(ctx *zedrouterContext) {
	ctx.appStatsMutex.Lock()
	if !ctx.appCollectStatsRunning {
		ctx.appCollectStatsRunning = true
		ctx.appStatsMutex.Unlock()
		log.Functionf("Creating %s at %s", "appStatusAndLogCollect",
			agentlog.GetMyStack())
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
		log.Functionf("checkAppStopStatsCollect: no stats IP anymore. stop and exit out")
		ctx.appCollectStatsRunning = false
		ctx.appStatsMutex.Unlock()
		return items, true
	}
	ctx.appStatsMutex.Unlock()
	return items, false
}

func getAppContainerStats(status types.AppNetworkStatus, cli *client.Client, containers []apitypes.Container) types.AppContainerMetrics {
	var acMetrics types.AppContainerMetrics

	for _, container := range containers {
		// the main purpose of Inspect is to obtain the container start time for CPU stats
		cjson, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			log.Errorf("getAppContainerStats: container inspect for %s, error %v", container.ID, err)
			continue
		}
		startTime, _ := time.Parse(time.RFC3339Nano, cjson.State.StartedAt)

		stats, err := cli.ContainerStats(context.Background(), container.ID, false)
		if err != nil {
			log.Errorf("getAppContainerStats: container stats for %s, error %v\n", container.Names[0], err)
			continue
		}

		acStats, err := processAppContainerStats(stats, container, startTime)
		if err != nil {
			log.Errorf("getAppContainerStats: process stats for %s, error %v\n", container.Names[0], err)
			continue
		}
		log.Tracef("getAppContainerStats: container stats %v", acStats)
		acMetrics.StatsList = append(acMetrics.StatsList, acStats)
	}

	return acMetrics
}

func processAppContainerStats(stats apitypes.ContainerStats, container apitypes.Container, startTime time.Time) (types.AppContainerStats, error) {
	var acStats types.AppContainerStats
	var v *apitypes.StatsJSON

	dec := json.NewDecoder(stats.Body)
	err := dec.Decode(&v)
	if err != nil {
		return acStats, err
	}

	acStats.ContainerName = strings.Trim(container.Names[0], "/")
	acStats.Status = container.Status

	acStats.Pids = uint32(v.PidsStats.Current)

	// Container CPU stats
	acStats.CPUTotal = v.CPUStats.CPUUsage.TotalUsage
	acStats.SystemCPUTotal = v.CPUStats.SystemUsage
	acStats.Uptime = startTime.UnixNano()

	// Container memory stats, convert bytes to Mbytes
	acStats.UsedMem = uint32(utils.RoundToMbytes(v.MemoryStats.Usage))
	acStats.AllocatedMem = uint32(utils.RoundToMbytes(v.MemoryStats.Limit))

	// Container network stats, in bytes
	networks := v.Networks
	for _, n := range networks {
		acStats.RxBytes += n.RxBytes
		acStats.TxBytes += n.TxBytes
	}

	// Container Block IO stats, convert bytes to Mbytes
	blkioStats := v.BlkioStats
	for _, bioEntry := range blkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(bioEntry.Op) {
		case "read":
			acStats.ReadBytes += bioEntry.Value
		case "write":
			acStats.WriteBytes += bioEntry.Value
		}
	}
	acStats.ReadBytes = utils.RoundToMbytes(acStats.ReadBytes)
	acStats.WriteBytes = utils.RoundToMbytes(acStats.WriteBytes)

	return acStats, nil
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
			log.Functionf("appStatsMayNeedReinstallACL: same app, skip")
			continue
		}
		if cfg.GetStatsIPAddr != nil {
			appConfigContainerStatsACL(cfg.GetStatsIPAddr, true)
			appConfigContainerStatsACL(cfg.GetStatsIPAddr, false)
			log.Functionf("appStatsMayNeedReinstallACL: reinstall %s\n", cfg.GetStatsIPAddr.String())
		}
	}
}

func getAppContainerLogs(ctx *zedrouterContext, status types.AppNetworkStatus, last map[string]time.Time, cli *client.Client, containers []apitypes.Container) int {
	var buf bytes.Buffer
	var numlogs int

	for _, container := range containers {
		var lasttime, newtime, message string
		containerName := strings.Trim(container.Names[0], "/")
		if lt, ok := last[containerName]; ok {
			lasttime = lt.Format(time.RFC3339Nano)
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
		numlogs += len(logLines)
		log.Tracef("getAppContainerLogs: container %s, lasttime %s, lines %d", containerName, lasttime, len(logLines))
		for _, line := range logLines {
			sline := strings.SplitN(line, " ", 2)
			time := sline[0]
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
				// insert container-name, app-UUID and module timestamp in log to be processed by newlogd
				// use customized aclog independent of pillar logger
				aclogger := ctx.aclog.WithFields(logrus.Fields{
					"appuuid":       status.UUIDandVersion.UUID.String(),
					"containername": containerName,
					"eventtime":     time,
				})
				aclogger.Infof("%s", message)
			}
		}
		// remember the last entry time by a container
		if newtime != "" {
			t, err := time.Parse(time.RFC3339Nano, newtime)
			if err != nil {
				log.Errorf("getAppContainerLogs: time parse error %v", err)
				t = time.Now()
			}
			last[containerName] = t.Add(2 * time.Nanosecond) // skip the last timestamp next round
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
	return numlogs
}

func getAppContainers(status types.AppNetworkStatus) (*client.Client, []apitypes.Container, error) {
	containerEndpoint := "tcp://" + status.GetStatsIPAddr.String() + ":" + strconv.Itoa(DOCKERAPIPORT)
	cli, err := client.NewClientWithOpts(
		client.WithHost(containerEndpoint),
		client.WithVersion(DOCKERAPIVERSION),
		client.WithHTTPClient(&http.Client{}))
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
