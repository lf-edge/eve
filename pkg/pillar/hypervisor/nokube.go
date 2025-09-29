// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !k

package hypervisor

const (
	// KubevirtHypervisorName is a name of the imaginary EVE 'k' hypervisor
	KubevirtHypervisorName = "k"
)

// newKubevirt in this file is just stub for non EVE-k builds.
func newKubevirt() Hypervisor {
	panic("EVE-k hypervisor code is not built")
}
