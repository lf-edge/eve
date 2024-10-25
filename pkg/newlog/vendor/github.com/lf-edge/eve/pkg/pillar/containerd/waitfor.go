// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package containerd

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// WaitForUserContainerd waits until user containerd started
func WaitForUserContainerd(ps *pubsub.PubSub, log *base.LogObject, agentName string, warningTime, errorTime time.Duration) error {
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)
	checkTicker := time.NewTicker(5 * time.Second)
	initialized := false

	for !initialized {
		log.Noticeln("Waiting for user containerd socket initialized")
		select {
		case <-checkTicker.C:
			ctrdClient, err := NewContainerdClient(true)
			if err != nil {
				log.Tracef("user containerd not ready: %v", err)
				continue
			}
			_ = ctrdClient.CloseClient()
			initialized = true
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	stillRunning.Stop()
	return nil
}
