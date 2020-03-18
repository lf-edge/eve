// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	dom0Name = "Domain-0"
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
	agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			getAndPublishMetrics(ctx, hyper)
			pubsub.CheckMaxTimeTopic(agentName+"metrics", "publishMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)
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
	ctx.pubHostMemory.Publish("global", hm)
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
