// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/cpu"
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
	now := time.Now()
	for domainName, dm := range dmList {
		uuid, err := types.DomainnameToUUID(domainName)
		if err != nil {
			log.Errorf("domainname %s: %s", domainName, err)
			continue
		}
		dm.UUIDandVersion.UUID = uuid
		status := lookupDomainStatusByUUID(ctx, uuid)
		if status != nil {
			dm.UUIDandVersion.Version = status.UUIDandVersion.Version
			dm.Activated = status.Activated
		}
		if !dm.Activated {
			// We clear the memory so it doesn't accidentally get
			// reported.  We keep the CPUTotal and AvailableMemory
			dm.UsedMemory = 0
			dm.UsedMemoryPercent = 0
		}
		dm.LastHeard = now
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}
	// Which ones did not report hence are gone?
	items := ctx.pubDomainMetric.GetAll()
	for _, m := range items {
		dm := m.(types.DomainMetric)
		if dm.LastHeard.Equal(now) || dm.UUIDandVersion.UUID == nilUUID {
			continue
		}
		log.Functionf("Found unheard DomainMetrics for %s", dm.Key())
		status := lookupDomainStatus(ctx, dm.Key())
		if status == nil {
			ctx.pubDomainMetric.Unpublish(dm.Key())
			continue
		}
		dm.Activated = false
		// We clear the memory so it doesn't accidentally get reported
		// We keep the CPUTotal and AvailableMemory
		dm.UsedMemory = 0
		dm.UsedMemoryPercent = 0
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}
	hm, _ := hyper.GetHostCPUMem()
	if hyper.Name() != "xen" {
		// the the hypervisor other than Xen, we don't have the Dom0 stats. Get the host
		// cpu and memory for the device here
		formatAndPublishHostCPUMem(ctx, hm, now)
	}
	ctx.pubHostMemory.Publish("global", hm)
}

func formatAndPublishHostCPUMem(ctx *domainContext, hm types.HostMemory, now time.Time) {
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
	if err != nil {
		log.Errorf("getAndPublishMetrics: cpu.Counts failed: %v", err)
		return
	}
	if CPUnum == 0 {
		// Assume 1 i.e. don't scale busy
		log.Warnf("getAndPublishMetrics: cpu count zero")
	} else {
		busy /= float64(CPUnum)
	}

	dm := types.DomainMetric{
		UUIDandVersion:    hostUUID,
		CPUTotal:          uint64(busy),
		UsedMemory:        uint32(used),
		AvailableMemory:   uint32(hm.FreeMemoryMB),
		UsedMemoryPercent: usedPerc,
		LastHeard:         now,
		Activated:         true,
	}
	log.Tracef("formatAndPublishHostCPUMem: hostcpu, dm %+v, CPU num %d", dm, CPUnum)
	ctx.pubDomainMetric.Publish(dm.Key(), dm)
}
