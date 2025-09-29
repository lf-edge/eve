// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// An alternate path to force a drain status in the event of a drain issue.
const forceNodeDrainPath string = "/persist/kube-status/force-NodeDrainStatus-global.json"

// RequestNodeDrain generates the NodeDrainRequest object and publishes it
func RequestNodeDrain(pubNodeDrainRequest pubsub.Publication, requester DrainRequester, context string) error {
	drainReq := NodeDrainRequest{
		RequestedAt: time.Now(),
		RequestedBy: requester,
		Context:     context,
	}
	err := pubNodeDrainRequest.Publish("global", drainReq)
	if err != nil {
		return fmt.Errorf("RequestNodeDrain: error publishing drain request: %v", err)
	}
	return nil
}

// GetDrainStatusOverride : an alternate way to set drain status for debug
func GetDrainStatusOverride(log *base.LogObject) *NodeDrainStatus {
	if _, err := os.Stat(forceNodeDrainPath); err != nil {
		return nil
	}
	b, err := os.ReadFile(forceNodeDrainPath)
	if err != nil {
		log.Warnf("Unable to read %s:%v", forceNodeDrainPath, err)
		return nil
	}
	cfg := NodeDrainStatus{}
	err = json.Unmarshal(b, &cfg)
	if err != nil {
		log.Warnf("Unable to Unmarshal %s to NodeDrainStatus: %v", forceNodeDrainPath, err)
		return nil
	}
	if cfg.Status == COMPLETE {
		err = os.Remove(forceNodeDrainPath)
		if err != nil {
			log.Warnf("could not remove %s: %v", forceNodeDrainPath, err)
		}
	}
	return &cfg
}

// CleanupDrainStatusOverride is used at microservice startup to cleanup
// a previously user written override file
func CleanupDrainStatusOverride(log *base.LogObject) {
	if _, err := os.Stat(forceNodeDrainPath); err != nil {
		return
	}
	err := os.Remove(forceNodeDrainPath)
	if err != nil {
		log.Warnf("CleanupDrainStatusOverride could not remove %s: %v", forceNodeDrainPath, err)
		return
	}
	return
}

// DrainStatusFaultInjectionWait while this file exists, wait in the drain status goroutine
func DrainStatusFaultInjectionWait() bool {
	injectFaultPath := "/tmp/DrainStatus_FaultInjection_Wait"
	if _, err := os.Stat(injectFaultPath); err == nil {
		return true
	}
	return false
}

// GetNodeDrainStatus is a wrapper to either return latest NodeDrainStatus
//
//	or return a forced status from /persist/force-NodeDrainStatus-global.json
func GetNodeDrainStatus(subNodeDrainStatus pubsub.Subscription, log *base.LogObject) *NodeDrainStatus {
	override := GetDrainStatusOverride(log)
	if override != nil {
		return override
	}

	items := subNodeDrainStatus.GetAll()
	glbStatus, ok := items["global"].(NodeDrainStatus)
	if !ok {
		// This should only be expected in EVE-k builds
		// and only very early in boot (before zedkube starts)
		return &NodeDrainStatus{Status: UNKNOWN, RequestedBy: NONE}
	}
	return &glbStatus
}
