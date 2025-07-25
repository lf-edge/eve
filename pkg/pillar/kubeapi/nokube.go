// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !kubevirt

package kubeapi

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// WaitForKubernetes in this file is just stub for non-kubevirt hypervisors.
func WaitForKubernetes(string, *pubsub.PubSub, *time.Ticker,
	...pubsub.ChannelWatch) error {
	panic("WaitForKubernetes is not built")
}

// CleanupStaleVMIRs in this file is just stub for non-kubevirt hypervisors.
func CleanupStaleVMIRs() (int, error) {
	panic("CleanupStaleVMIRs is not built")
}

// GetPVCList in this file is just stub for non-kubevirt hypervisors.
func GetPVCList(*base.LogObject) ([]string, error) {
	panic("GetPVCList is not built")
}

// RequestNodeDrain is a stub for non-kubevirt builds
func RequestNodeDrain(pubsub.Publication, DrainRequester, string) error {
	// Nothing to do here, just noop
	return fmt.Errorf("nokube requested drain, should not get here")
}

// GetNodeDrainStatus is a stub for non-kubevirt builds
func GetNodeDrainStatus(pubsub.Subscription, *base.LogObject) *NodeDrainStatus {
	// No need to query for inprogress operations, just a noop
	return &NodeDrainStatus{Status: NOTSUPPORTED}
}

// IsClusterMode  is a stub for non-kubevirt builds
func IsClusterMode() bool {
	return false
}
