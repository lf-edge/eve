// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

// ACRNHypervisorName is a name of acrn hypervisor
const ACRNHypervisorName = "acrn"

type acrnContext struct {
	nullContext
}

func newAcrn() Hypervisor {
	return acrnContext{}
}

// Name returns the name of this hypervisor implementation
func (ctx acrnContext) Name() string {
	return ACRNHypervisorName
}
