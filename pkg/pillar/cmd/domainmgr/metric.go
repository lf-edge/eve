// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/mackerelio/go-osstat/cpu"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
)

const (
	dom0Name        = "Domain-0"
	nonXenCPUfactor = 50
)

// Run a periodic post of the metrics
func metricsTimerTask(ctx *domainContext, hyper hypervisor.Hypervisor) {
	log.Infoln("starting metrics timer task")
	getAndPublishMetrics(ctx, hyper)

	// Publish 4X more often than zedagent publishes to controller
	interval := time.Duration(ctx.metricInterval) * time.Second
	max := float64(interval) / 4
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(agentName+"metrics", warningTime, errorTime)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			getAndPublishMetrics(ctx, hyper)
			ctx.ps.CheckMaxTimeTopic(agentName+"metrics", "publishMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(agentName+"metrics", warningTime, errorTime)
	}
}

func getAndPublishMetrics(ctx *domainContext, hyper hypervisor.Hypervisor) {
	isXen := hyper.Name() == "xen"
	dmList, _ := hyper.GetDomsCPUMem()
	for domainName, dm := range dmList {
		uuid, err := domainnameToUUID(ctx, domainName)
		if err != nil {
			log.Errorf("domainname %s: %s", domainName, err)
			continue
		}
		dm.UUIDandVersion.UUID = uuid
		if !isXen {
			// XXX from observation, the dm.CPUTotal gets from the kvm hypervisor containerd stat is
			// hundreds percentage of the app uptime in seconds.
			// Assume the CPUTotal value and the app CPU usage is proportional, this nonXenCPUfactor
			// is obtained by run the same App under Xen and KVM in comparison to be used as
			// an approcimation.
			dm.CPUTotal = dm.CPUTotal / nonXenCPUfactor
		}
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}

	hm, _ := hyper.GetHostCPUMem()
	if !isXen {
		// the the hypervisor other than Xen, we don't have the Dom0 stats. Get the host
		// cpu and memory for the device here
		formatAndPublishHostCPUMem(ctx, hm)
	}
	ctx.pubHostMemory.Publish("global", hm)
}

func formatAndPublishHostCPUMem(ctx *domainContext, hm types.HostMemory) {
	cpuInfo, err := cpu.Get()
	if err != nil {
		log.Errorf("getAndPublishMetrics: cpu Get error %v", err)
		return
	}

	used := hm.TotalMemoryMB - hm.FreeMemoryMB
	var usedPerc float64
	if hm.TotalMemoryMB > 0 {
		usedPerc = float64(used * 100.0 / hm.TotalMemoryMB)
	}
	var hostUUID types.UUIDandVersion
	hostUUID.UUID = nilUUID
	uptime, _ := host.Uptime()
	cpuUsage := cpuInfo.User + cpuInfo.System + cpuInfo.Iowait + cpuInfo.Softirq + cpuInfo.Irq
	cpuUsageSec := (cpuUsage * uptime) / cpuInfo.Total

	dm := types.DomainMetric{
		UUIDandVersion:    hostUUID,
		CPUTotal:          cpuUsageSec,
		UsedMemory:        uint32(used),
		AvailableMemory:   uint32(hm.FreeMemoryMB),
		UsedMemoryPercent: usedPerc,
	}
	log.Debugf("formatHostCPUMem: dm %+v, uptime %d, cpu total %d, usage %d, guest %d",
		dm, uptime, cpuInfo.Total, cpuUsage, cpuInfo.Guest)
	ctx.pubDomainMetric.Publish(dm.Key(), dm)
}

// Returns zero for the host/overhead
func domainnameToUUID(ctx *domainContext, domainName string) (uuid.UUID, error) {
	if domainName == dom0Name {
		return uuid.UUID{}, nil
	}
	pub := ctx.pubDomainStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.DomainStatus)
		if status.DomainName == domainName {
			return status.UUIDandVersion.UUID, nil
		}
	}
	return uuid.UUID{}, fmt.Errorf("Unknown domainname %s", domainName)
}
