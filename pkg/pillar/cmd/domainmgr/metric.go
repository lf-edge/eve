// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/cpu"
)

const (
	dom0Name = "Domain-0"
)

// Run a periodic post of the metrics
func metricsTimerTask(ctx *domainContext, hyper hypervisor.Hypervisor) {
	log.Functionln("starting metrics timer task")
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
	dmList, _ := hyper.GetDomsCPUMem()
	for domainName, dm := range dmList {
		uuid, err := domainnameToUUID(ctx, domainName)
		if err != nil {
			log.Errorf("domainname %s: %s", domainName, err)
			continue
		}
		dm.UUIDandVersion.UUID = uuid
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}

	hm, _ := hyper.GetHostCPUMem()
	if hyper.Name() != "xen" {
		// the the hypervisor other than Xen, we don't have the Dom0 stats. Get the host
		// cpu and memory for the device here
		formatAndPublishHostCPUMem(ctx, hm)
	}
	ctx.pubHostMemory.Publish("global", hm)
}

func formatAndPublishHostCPUMem(ctx *domainContext, hm types.HostMemory) {
	var hostUUID types.UUIDandVersion
	var usedPerc, busy float64
	used := hm.TotalMemoryMB - hm.FreeMemoryMB
	if hm.TotalMemoryMB > 0 {
		usedPerc = float64(used * 100.0 / hm.TotalMemoryMB)
	}
	hostUUID.UUID = nilUUID
	cpuStat, err := cpu.Times(false)
	if err != nil {
		log.Errorf("getAndPublishMetrics: cpu Get error %v", err)

		return
	}

	for _, t := range cpuStat {
		busy += t.User + t.System + t.Nice + t.Irq + t.Softirq
	}

	CPUnum, err := cpu.Counts(false)
	if err != nil || CPUnum == 0 {
		log.Errorf("getAndPublishMetrics: cpu count %d, error %v", CPUnum, err)

		return
	}

	busy /= float64(CPUnum)

	dm := types.DomainMetric{
		UUIDandVersion:    hostUUID,
		CPUTotal:          uint64(busy),
		UsedMemory:        uint32(used),
		AvailableMemory:   uint32(hm.FreeMemoryMB),
		UsedMemoryPercent: usedPerc,
	}
	log.Tracef("formatAndPublishHostCPUMem: hostcpu, dm %+v, CPU num %d", dm, CPUnum)
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
