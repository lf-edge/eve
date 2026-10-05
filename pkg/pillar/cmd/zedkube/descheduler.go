// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// deschedulerBootWindow is how long after kubernetes comes ready the boot
// event may still fire. A node that never becomes healthy enough to
// receive apps should stop asking rather than retry for its whole uptime.
const deschedulerBootWindow = 30 * time.Minute

// deschedulePendingLogEvery bounds how often a run that cannot start yet
// says why.
const deschedulePendingLogEvery = time.Minute

// deschedulerInputs is everything the pending decision reads.
type deschedulerInputs struct {
	events             types.VmiDescheduleConfig
	triggeredSinceBoot bool
	bootWindowEnd      time.Time
	// misplaced is set while the periodic event is enabled and an app
	// designated to this node runs on another node.
	misplaced bool
	// readySince is when this node last became ready to receive apps
	// without interruption since. Zero while it is not.
	readySince time.Time
	// lastPlacementRun is when placement was last restored.
	lastPlacementRun time.Time
	// settle is how long the node must have been ready to receive apps
	// before the periodic event acts, and the minimum time between two of
	// its runs (KubernetesVmiDeschedulePeriodicSettle).
	settle time.Duration
	now    time.Time
}

// deschedulerReason names why a run is owed, for the log.
type deschedulerReason string

const (
	deschedulerReasonNone     deschedulerReason = ""
	deschedulerReasonBoot     deschedulerReason = "boot"
	deschedulerReasonPeriodic deschedulerReason = "periodic"
)

// bootDue reports whether the boot event wants a run: once per boot,
// within the window after kubernetes came ready, and only if configured.
// zedkube is the only place that knows kubernetes just became ready
// (bootWindowEnd), so events.OnBoot is read live, here, each tick.
func bootDue(in deschedulerInputs) bool {
	return in.events.OnBoot && !in.triggeredSinceBoot &&
		!in.bootWindowEnd.IsZero() && in.now.Before(in.bootWindowEnd)
}

// deschedulerPending reports whether a run is owed, and why.
//
// The periodic event is owed while an app is misplaced, once this node has
// been ready to receive apps for settle, and not again until settle after
// the last time it acted: each move restarts the app, so a node that keeps coming
// and going must not pull apps back and forth, and an app that does not
// move must not be retried every tick.
func deschedulerPending(in deschedulerInputs) (deschedulerReason, bool) {
	if bootDue(in) {
		return deschedulerReasonBoot, true
	}
	if in.events.OnPeriodic && in.misplaced && !in.readySince.IsZero() &&
		in.now.Sub(in.readySince) >= in.settle &&
		(in.lastPlacementRun.IsZero() || in.now.Sub(in.lastPlacementRun) >= in.settle) {
		return deschedulerReasonPeriodic, true
	}
	return deschedulerReasonNone, false
}

// runDeschedulerIfPending is the single place app placement is restored.
// Called from the app-status tick, which already runs while kubernetes is
// serving. Both events trigger the same restorePlacement; they differ only
// in when: boot once per boot, as soon as the node can receive apps, and
// periodic whenever an app is misplaced, once the node has settled.
func (z *zedkube) runDeschedulerIfPending(wdFunc func()) {
	in := z.deschedulerInputs()
	if !bootDue(in) && !in.misplaced {
		z.placementReadySince = time.Time{}
		return
	}
	ready, why, err := kubeapi.IsDeschedulerReadyWithReason(log, z.nodeName)
	if err != nil {
		log.Errorf("runDeschedulerIfPending: readiness check: %v", err)
	}
	if err != nil || !ready {
		z.placementReadySince = time.Time{}
		// Rate-limited: this retries every tick, and a node that needs a
		// minute to settle would otherwise say so six times a minute.
		if err == nil && time.Since(z.deschedulePendingLogged) > deschedulePendingLogEvery {
			z.deschedulePendingLogged = time.Now()
			log.Noticef("runDeschedulerIfPending: waiting to receive apps: %s", why)
		}
		return
	}
	if z.placementReadySince.IsZero() {
		z.placementReadySince = in.now
	}
	in.readySince = z.placementReadySince

	reason, pending := deschedulerPending(in)
	if !pending {
		return
	}
	log.Noticef("runDeschedulerIfPending: restoring app placement (%s)", reason)
	switch reason {
	case deschedulerReasonBoot:
		// Done only if it went through: it is not retried otherwise.
		z.triggeredSinceBoot = z.restorePlacement(wdFunc)
	case deschedulerReasonPeriodic:
		z.lastPlacementRun = in.now
		z.restorePlacement(wdFunc)
	}
}

// vmiDescheduleEvents is the trigger set in effect: the operator's, read
// back from what handleVmiDescheduleEventsOverride published, with the
// periodic event always enabled in a 2-node HA cluster, where the placement
// of an app is what keeps it running (see isTwoNodeHACluster). Derived here
// rather than published, as the cluster config arrives independently of the
// global config.
func (z *zedkube) vmiDescheduleEvents() types.VmiDescheduleConfig {
	var events types.VmiDescheduleConfig
	if v, ok := z.pubKubeConfig.GetAll()["global"].(types.KubeConfig); ok {
		events = v.VmiDescheduleEvents
	}
	if z.isTwoNodeHACluster() {
		events.OnPeriodic = true
	}
	return events
}

// deschedulerInputs snapshots what the decision reads, so the decision
// itself can be tested without a pubsub publication.
func (z *zedkube) deschedulerInputs() deschedulerInputs {
	events := z.vmiDescheduleEvents()
	return deschedulerInputs{
		events:             events,
		triggeredSinceBoot: z.triggeredSinceBoot,
		bootWindowEnd:      z.deschedulerBootWindowEnd,
		misplaced:          events.OnPeriodic && len(z.misplacedApps()) > 0,
		readySince:         z.placementReadySince,
		lastPlacementRun:   z.lastPlacementRun,
		settle: time.Duration(z.globalConfig.GlobalValueInt(
			types.KubernetesVmiDeschedulePeriodicSettle)) * time.Second,
		now: time.Now(),
	}
}
