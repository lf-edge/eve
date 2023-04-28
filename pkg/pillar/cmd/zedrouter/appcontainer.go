// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

// dockerAPIPort - unencrypted docker socket for remote password-less access
const dockerAPIPort int = 2375

// dockerAPIVersion - docker API version used
const dockerAPIVersion string = "1.40"

// check if we need to launch the goroutine to collect App container stats
func (z *zedrouter) checkAppContainerStatsCollecting(config *types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	var changed bool
	if config != nil {
		if !status.GetStatsIPAddr.Equal(config.GetStatsIPAddr) {
			status.GetStatsIPAddr = config.GetStatsIPAddr
			changed = true
		}
	} else {
		if status.GetStatsIPAddr != nil {
			status.GetStatsIPAddr = nil
			changed = true
		}
	}
	if !changed {
		return
	}
	z.publishAppNetworkStatus(status)
	if status.GetStatsIPAddr != nil {
		z.ensureAppContainerStatsAreCollected()
	}
}

// goroutine for App container stats collection
func (z *zedrouter) collectAppContainerStats() {
	z.log.Functionf("collectAppContainerStats: containerStats, started")
	// cache the container last timestamp of log entries of the batch
	lastLogTime := make(map[string]time.Time)
	appStatsCollectTimer := time.NewTimer(
		time.Duration(z.appContainerStatsInterval) * time.Second)
	for {
		select {
		case <-appStatsCollectTimer.C:
			items, stopped := z.maybeStopAppContainerStatsCollecting()
			if stopped {
				return
			}

			var acNum, numlogs int
			collectTime := time.Now() // all apps collection assign the same timestamp
			for _, st := range items {
				status := st.(types.AppNetworkStatus)
				if status.GetStatsIPAddr != nil {
					// get a list of containers and client handle
					cli, containers, err := z.getAppContainers(status)
					if err != nil {
						z.log.Errorf(
							"collectAppContainerStats: can't get App Containers %s on %s, %v",
							status.UUIDandVersion.UUID.String(), status.GetStatsIPAddr.String(),
							err)
						continue
					}
					acNum += len(containers)

					// collect container stats, and publish to zedclient
					acMetrics := z.getAppContainerStats(cli, containers)
					if len(acMetrics.StatsList) > 0 {
						acMetrics.UUIDandVersion = status.UUIDandVersion
						acMetrics.CollectTime = collectTime
						z.pubAppContainerStats.Publish(acMetrics.Key(), acMetrics)
					}

					// collect container logs and send through the logging system
					numlogs += z.getAppContainerLogs(status, lastLogTime, cli, containers)
				}
			}
			// log output every 5 min, see this goroutine running status and number
			// of containers from App
			z.log.Functionf("collectAppContainerStats: containerStats, %d processed. "+
				"total log entries %d, reset timer", acNum, numlogs)

			appStatsCollectTimer = time.NewTimer(
				time.Duration(z.appContainerStatsInterval) * time.Second)
		}
	}
}

func (z *zedrouter) ensureAppContainerStatsAreCollected() {
	z.appContainerStatsMutex.Lock()
	if !z.appContainerStatsCollecting {
		z.appContainerStatsCollecting = true
		z.appContainerStatsMutex.Unlock()
		z.log.Functionf("Creating %s at %s", "appStatusAndLogCollect",
			agentlog.GetMyStack())
		go z.collectAppContainerStats()
	} else {
		z.appContainerStatsMutex.Unlock()
	}
}

func (z *zedrouter) maybeStopAppContainerStatsCollecting() (map[string]interface{}, bool) {
	var numStatsIP int
	z.appContainerStatsMutex.Lock()
	pub := z.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		if status.GetStatsIPAddr != nil {
			numStatsIP++
		}
	}
	if numStatsIP == 0 {
		z.log.Functionf("maybeStopAppContainerStatsCollecting: no stats IP anymore. " +
			"stop and exit out")
		z.appContainerStatsCollecting = false
		z.appContainerStatsMutex.Unlock()
		return items, true
	}
	z.appContainerStatsMutex.Unlock()
	return items, false
}

func (z *zedrouter) getAppContainerStats(cli *client.Client,
	containers []apitypes.Container) types.AppContainerMetrics {
	var acMetrics types.AppContainerMetrics

	for _, container := range containers {
		// the main purpose of Inspect is to obtain the container start time for CPU stats
		cjson, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			z.log.Errorf("getAppContainerStats: container inspect for %s, error %v",
				container.ID, err)
			continue
		}
		startTime, _ := time.Parse(time.RFC3339Nano, cjson.State.StartedAt)

		stats, err := cli.ContainerStats(context.Background(), container.ID, false)
		if err != nil {
			z.log.Errorf("getAppContainerStats: container stats for %s, error %v\n",
				container.Names[0], err)
			continue
		}

		acStats, err := z.processAppContainerStats(stats, container, startTime)
		if err != nil {
			z.log.Errorf("getAppContainerStats: process stats for %s, error %v\n",
				container.Names[0], err)
			continue
		}
		z.log.Tracef("getAppContainerStats: container stats %v", acStats)
		acMetrics.StatsList = append(acMetrics.StatsList, acStats)
	}

	return acMetrics
}

func (z *zedrouter) processAppContainerStats(stats apitypes.ContainerStats,
	container apitypes.Container, startTime time.Time) (types.AppContainerStats, error) {
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

func (z *zedrouter) getAppContainerLogs(status types.AppNetworkStatus,
	last map[string]time.Time, cli *client.Client, containers []apitypes.Container) int {
	var buf bytes.Buffer
	var numlogs int

	for _, container := range containers {
		var lasttime, newtime, message string
		containerName := strings.Trim(container.Names[0], "/")
		if lt, ok := last[containerName]; ok {
			lasttime = lt.Format(time.RFC3339Nano)
		}
		out, err := cli.ContainerLogs(context.Background(), container.ID,
			apitypes.ContainerLogsOptions{
				ShowStdout: true,
				ShowStderr: true,
				Timestamps: true,
				Since:      lasttime,
			})
		if err != nil {
			z.log.Errorf("getAppContainerLogs: log output error %v", err)
			continue
		}

		stdcopy.StdCopy(&buf, &buf, io.LimitReader(out, 100000))
		logLines := strings.Split(buf.String(), "\n")
		numlogs += len(logLines)
		z.log.Tracef("getAppContainerLogs: container %s, lasttime %s, lines %d",
			containerName, lasttime, len(logLines))
		for _, line := range logLines {
			sline := strings.SplitN(line, " ", 2)
			time := sline[0]
			if len(time) > 0 && len(sline) == 2 {
				newtime = time
				// Some message has timestamp like:
				//	[\u003c6\u003e 2020-06-23 22:29:01.871 +00:00 [INF] - ]
				// Remove the timestamp in message if any since we always have timestamp
				msg := strings.SplitN(sline[1], " +00:00 [", 2)
				if len(msg) > 1 {
					message = " [" + msg[1]
				} else {
					message = msg[0]
				}
				// Insert container-name, app-UUID and module timestamp in log
				// to be processed by newlogd.
				// Use customized appContainerLogger independent of pillar logger
				aclogger := z.appContainerLogger.WithFields(logrus.Fields{
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
				z.log.Errorf("getAppContainerLogs: time parse error %v", err)
				t = time.Now()
			}
			// skip the last timestamp next round
			last[containerName] = t.Add(2 * time.Nanosecond)
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

func (z *zedrouter) getAppContainers(status types.AppNetworkStatus) (
	*client.Client, []apitypes.Container, error) {
	containerEndpoint := "tcp://" + status.GetStatsIPAddr.String() +
		":" + strconv.Itoa(dockerAPIPort)
	cli, err := client.NewClient(containerEndpoint, dockerAPIVersion, nil, nil)
	if err != nil {
		z.log.Errorf("getAppContainers: client create failed, error %v", err)
		return nil, nil, err
	}

	containers, err := cli.ContainerList(
		context.Background(), apitypes.ContainerListOptions{})
	if err != nil {
		z.log.Errorf("getAppContainers: Container list error %v", err)
		return nil, nil, err
	}

	return cli, containers, nil
}
