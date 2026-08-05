// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// storageWaitPending is the condition reported while the EVE-k cluster-storage
// wait is still running, as opposed to having given up.
const storageWaitPending = "waiting for cluster storage (longhorn+CDI)"

// initStatusPublications creates the publications volumeMgrStatusTask needs.
// They are created ahead of the EVE-k cluster-storage wait, rather than with the
// rest of the publications further down Run(), because the task reports through
// them while that wait is still in progress.
func initStatusPublications(ps *pubsub.PubSub, ctx *volumemgrContext) {
	pubVolumeMgrStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeMgrStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeMgrStatus = pubVolumeMgrStatus

	pubContentTreeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.ContentTreeStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubContentTreeStatus = pubContentTreeStatus

	pubVolumeStatus, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.VolumeStatus{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubVolumeStatus = pubVolumeStatus

	pubDiskMetric, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DiskMetric{},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDiskMetric = pubDiskMetric
}

// volumeMgrStatusTask publishes VolumeMgrStatus for the lifetime of volumemgr:
// once immediately, then on every trigger from the startup path and on a timer
// at the disk-metric interval so RemainingSpace keeps up with actual usage.
//
// It is the sole publisher of the topic and runs separately from
// diskMetricsTimerTask so that it can start before the EVE-k cluster-storage
// wait, which the disk-metrics task runs after. No watchdog is registered: a
// stall here leaves a stale status, which does not warrant rebooting the device.
func volumeMgrStatusTask(ctx *volumemgrContext) {
	log.Functionln("starting volumeMgrStatusTask")

	interval := time.Duration(ctx.globalConfig.GlobalValueInt(
		types.DiskScanMetricInterval)) * time.Second
	maxInterval := float64(interval)
	minInterval := maxInterval * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(minInterval),
		time.Duration(maxInterval))

	for {
		publishVolumeMgrStatus(ctx)
		select {
		case <-ctx.statusTrigger:
		case <-ticker.C:
		}
	}
}

// publishVolumeMgrStatus publishes volumemgr's own status. A device whose
// remaining space cannot be determined publishes nothing rather than a zero,
// which nodeagent would read as a reason to enter MaintenanceMode.
func publishVolumeMgrStatus(ctx *volumemgrContext) {
	remaining, err := getRemainingDiskSpace(ctx)
	if err != nil {
		log.Error(err)
		return
	}
	st := ctx.volumeMgrStatus(remaining)
	ctx.pubVolumeMgrStatus.Publish(st.Key(), st)
}

// volumeMgrStatus describes volumemgr itself: whether storage is usable, the
// gate still outstanding when it is not, and the space left for volumes after
// everything reserved for EVE has been subtracted.
func (ctxPtr *volumemgrContext) volumeMgrStatus(remaining uint64) types.VolumeMgrStatus {
	ready, unmet := ctxPtr.storageReadiness()
	return types.VolumeMgrStatus{
		Name:           agentName,
		Initialized:    ready,
		UnmetCondition: unmet,
		RemainingSpace: remaining,
	}
}

// setStorageReadiness records the storage verdict and wakes the status task so
// the change is reported without waiting for the next tick.
func (ctxPtr *volumemgrContext) setStorageReadiness(ready bool, unmet string) {
	ctxPtr.storageMu.Lock()
	ctxPtr.storageReady = ready
	ctxPtr.storageUnmet = unmet
	ctxPtr.storageMu.Unlock()

	select {
	case ctxPtr.statusTrigger <- struct{}{}:
	default:
	}
}

// storageReadiness returns whether storage is usable and, when it is not, the
// outstanding gate.
func (ctxPtr *volumemgrContext) storageReadiness() (bool, string) {
	ctxPtr.storageMu.Lock()
	defer ctxPtr.storageMu.Unlock()
	return ctxPtr.storageReady, ctxPtr.storageUnmet
}
