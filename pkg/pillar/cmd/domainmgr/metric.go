// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/hypervisor"

	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/cpu"
)

const (
	warnMemoryWatermark = 80 //send warning in case of exceed memory percent limit
	// Publish 4X more often than zedagent publishes to controller
	// to reduce effect of quantization errors
	publishTickerDivider = 4
)

// Run a periodic post of the metrics
func metricsTimerTask(ctx *domainContext, hyper hypervisor.Hypervisor) {
	log.Functionln("starting metrics timer task")
	getAndPublishMetrics(ctx, hyper)

	oldMetricInterval := ctx.metricInterval
	calculateMinMax := func(metricInterval uint32) (time.Duration, time.Duration) {
		interval := time.Duration(metricInterval) * time.Second
		max := float64(interval) / publishTickerDivider
		min := max * 0.3
		return time.Duration(min), time.Duration(max)
	}

	ticker := flextimer.NewRangeTicker(calculateMinMax(ctx.metricInterval))

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
		if oldMetricInterval != ctx.metricInterval {
			log.Functionf("metricInterval updated from %d to %d", oldMetricInterval, ctx.metricInterval)
			oldMetricInterval = ctx.metricInterval
			ticker.UpdateRangeTicker(calculateMinMax(ctx.metricInterval))
		}
		ctx.ps.StillRunning(agentName+"metrics", warningTime, errorTime)
	}
}

func logWatermarks(ctx *domainContext, status *types.DomainStatus, dm *types.DomainMetric) {
	if status == nil {
		return
	}

	config := lookupDomainConfig(ctx, status.Key())
	if config == nil {
		return
	}

	var CurrMaxUsedMemory uint32
	st, _ := ctx.pubDomainMetric.Get(dm.Key())
	if st != nil {
		previousMetric := st.(types.DomainMetric)
		CurrMaxUsedMemory = previousMetric.MaxUsedMemory
	}

	if CurrMaxUsedMemory < dm.MaxUsedMemory && config.Memory != 0 {
		usedPercents := dm.MaxUsedMemory * 100 * 1024 / uint32(config.Memory)
		watermark := fmt.Sprintf("Memory watermark for %s increased: %d MiB,"+
			" app-memory %d MiB (%d%%), %.2f%% of cgroup limit",
			status.DomainName,
			dm.MaxUsedMemory, config.Memory>>10,
			usedPercents, dm.UsedMemoryPercent)
		if usedPercents >= warnMemoryWatermark || dm.UsedMemoryPercent >= warnMemoryWatermark {
			log.Warn(watermark)
		} else {
			// reduce log severity for cases when memory no exceed warnMemoryWatermark % of limit
			log.Function(watermark)
		}
	}
}

func getAndPublishMetrics(ctx *domainContext, hyper hypervisor.Hypervisor) {
	dmList, _ := hyper.GetDomsCPUMem()
	hm, err := hyper.GetHostCPUMem()
	if err != nil {
		log.Errorf("Cannot obtain HostCPUMem: %s", err)
		return
	}
	now := time.Now()
	for domainName, dm := range dmList {
		uuid, version, _, err := types.DomainnameToUUID(domainName)
		if err != nil {
			log.Errorf("domainname %s: %s", domainName, err)
			continue
		}
		dm.UUIDandVersion.UUID = uuid
		dm.UUIDandVersion.Version = version
		status := lookupDomainStatusByUUID(ctx, uuid)
		if status == nil && dm.UUIDandVersion.UUID != nilUUID {
			log.Warnf("Unknown metrics domainname %s",
				domainName)
			continue
		}
		if status != nil {
			if status.DomainName != domainName {
				log.Warnf("Ignoring metrics with wrong version %s vs. %s",
					domainName, status.DomainName)
				continue
			}
			dm.Activated = status.Activated
			// Scale the CPU nanoseconds based on the number of VCpus
			if status.VCpus != 0 {
				dm.CPUTotalNs /= uint64(status.VCpus)
				dm.CPUScaled = uint32(status.VCpus)
			}
			// XXX remove - this does not include qemu overhead
			// dm.AllocatedMB = uint32((status.Memory + 1023) / 1024)
		} else if dm.UUIDandVersion.UUID == nilUUID && hm.Ncpus != 0 {
			// Scale Xen Dom0 based CPUs seen by hypervisor
			dm.CPUTotalNs /= uint64(hm.Ncpus)
			dm.CPUScaled = hm.Ncpus
			dm.Activated = true
		}
		if !dm.Activated {
			// We clear the memory so it doesn't accidentally get
			// reported.  We keep the CPUTotalNs, AvailableMemory, and
			// AllocatedMB
			dm.UsedMemory = 0
			dm.MaxUsedMemory = 0
			dm.UsedMemoryPercent = 0
		}

		logWatermarks(ctx, status, &dm)

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
		// We keep the CPUTotalNs and AvailableMemory
		dm.UsedMemory = 0
		dm.UsedMemoryPercent = 0
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}
	if hyper.Name() != "xen" {
		// the the hypervisor other than Xen, we don't have the Dom0 stats in dmList. Get the host
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

	if hm.Ncpus != 0 {
		// Scale based on the CPUs seen by the hypervisor
		busy /= float64(hm.Ncpus)
	}

	const nanoSecToSec uint64 = 1000000000
	dm := types.DomainMetric{
		UUIDandVersion:    hostUUID,
		CPUTotalNs:        uint64(busy * float64(nanoSecToSec)),
		CPUScaled:         hm.Ncpus,
		UsedMemory:        uint32(used),
		AvailableMemory:   uint32(hm.FreeMemoryMB),
		UsedMemoryPercent: usedPerc,
		LastHeard:         now,
		Activated:         true,
	}
	log.Tracef("formatAndPublishHostCPUMem: hostcpu, dm %+v, CPU num %d busy %f", dm, hm.Ncpus, busy)
	ctx.pubDomainMetric.Publish(dm.Key(), dm)
}
