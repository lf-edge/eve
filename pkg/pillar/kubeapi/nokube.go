// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !kubevirt

package kubeapi

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// WaitForKubernetes in this file is just stub for non-kubevirt hypervisors.
func WaitForKubernetes(
	agentName string, ps *pubsub.PubSub, stillRunning *time.Ticker) error {
	panic("WaitForKubernetes is not built")
}

// CleanupStaleVMI in this file is just stub for non-kubevirt hypervisors.
func CleanupStaleVMI() (int, error) {
	panic("CleanupStaleVMI is not built")
}

// GetPVCList in this file is just stub for non-kubevirt hypervisors.
func GetPVCList(*base.LogObject) ([]string, error) {
	panic("GetPVCList is not built")
}
