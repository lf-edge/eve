// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !kubevirt

package hypervisor

import "github.com/sirupsen/logrus"

const (
	// KubevirtHypervisorName : Name of the kubevirt hypervisor
	KubevirtHypervisorName = "kubevirt"
)

// newKubevirt in this file is just stub for non-kubevirt hypervisors.
func newKubevirt() Hypervisor {
	logrus.Warn("Kubevirt hypervisor is not enabled")
	return nil
}
