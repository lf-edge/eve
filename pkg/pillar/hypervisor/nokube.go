// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !kubevirt

package hypervisor

const (
	KubevirtHypervisorName = "kubevirt"
)

// newKubevirt in this file is just stub for non-kubevirt hypervisors.
func newKubevirt() Hypervisor {
	panic("Hypervisor for kubevirt is not built")
}
