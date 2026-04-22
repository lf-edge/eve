// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
)

const deschedulerOnBootTimeout = 30 * time.Minute

// deschedulerOnBootWatcher polls cluster readiness and triggers the descheduler
// Job once per boot. It is only launched from Run() after WaitForKubernetes
// returns, so kubernetes is ready and OnBoot=true is guaranteed by the caller.
// It gives up after deschedulerOnBootTimeout so it does not run indefinitely
// if the cluster never reaches a fully healthy state this boot.
func (z *zedkube) deschedulerOnBootWatcher() {
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
