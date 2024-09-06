// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// RequestNodeDrain generates the NodeDrainRequest object and publishes it
func RequestNodeDrain(pubNodeDrainRequest pubsub.Publication, requester DrainRequester) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("RequestNodeDrain: can't get hostname %v", err)
	}
	drainReq := NodeDrainRequest{
		Hostname:    hostname,
		RequestedAt: time.Now(),
		RequestedBy: requester,
	}
	err = pubNodeDrainRequest.Publish("global", drainReq)
	if err != nil {
		return fmt.Errorf("RequestNodeDrain: error publishing drain request: %v", err)
	}
	return nil
}

// GetDrainStatusOverride : an alternate way to set drain status for debug
func GetDrainStatusOverride() *NodeDrainStatus {
	// An alternate path to force a drain status in the event of a drain issue.
	forceNodeDrainPath := "/tmp/force-NodeDrainStatus-global.json"
	if _, err := os.Stat(forceNodeDrainPath); err == nil {
		b, err := os.ReadFile(forceNodeDrainPath)
		if err == nil {
			cfg := NodeDrainStatus{}
			err = json.Unmarshal(b, &cfg)
			if err == nil {
				return &cfg
			}
		}
	}
	return nil
}

// GetNodeDrainStatus is a wrapper to either return latest NodeDrainStatus
//
//	or return a forced status from /persist/force-NodeDrainStatus-global.json
func GetNodeDrainStatus(subNodeDrainStatus pubsub.Subscription) *NodeDrainStatus {
	override := GetDrainStatusOverride()
	if override != nil {
		return override
	}

	items := subNodeDrainStatus.GetAll()
	glbStatus, ok := items["global"].(NodeDrainStatus)
	if !ok {
		// This should only be expected on an HV=kubevirt build
		// and only very early in boot (before zedkube starts)
		return &NodeDrainStatus{Status: UNKNOWN, RequestedBy: NONE}
	}
	return &glbStatus
}
