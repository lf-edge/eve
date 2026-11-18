// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
)

const deschedulerOnBootTimeout = 30 * time.Minute

// deschedulerOnBootWatcher polls cluster readiness and triggers the descheduler
// Job once per boot. It is only launched from Run() after WaitForKubernetes
// returns, so kubernetes is ready and OnBoot=true is guaranteed by the caller.
// It gives up after deschedulerOnBootTimeout so it does not run indefinitely
// if the cluster never reaches a fully healthy state this boot.
//
// It first waits, without a deadline, for kube-init's component update
// pass. The readiness checks below can all pass between two steps of a
// component upgrade, and bringing apps back onto this node then would have
// them attach volumes mid-upgrade. The pass can also outlast the timeout,
// which would otherwise mean no failback at all this boot.
func (z *zedkube) deschedulerOnBootWatcher() {
	if !z.kubeComponentsGate.Ready() {
		log.Noticef("deschedulerOnBootWatcher: waiting for the kube component update pass")
		_ = z.kubeComponentsGate.Wait(context.Background())
	}
	deadline := time.NewTimer(deschedulerOnBootTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		ready, err := kubeapi.IsDeschedulerReady(log, z.nodeName)
		if err != nil {
			log.Errorf("deschedulerOnBootWatcher: readiness check error: %v", err)
		}
		if ready {
			if err := kubeapi.TriggerDescheduler(log, z.nodeName); err != nil {
				log.Errorf("deschedulerOnBootWatcher: trigger error: %v", err)
			} else {
				return
			}
		}
		select {
		case <-deadline.C:
			log.Noticef("deschedulerOnBootWatcher: timed out after %s, giving up", deschedulerOnBootTimeout)
			return
		case <-ticker.C:
		}
	}
}
