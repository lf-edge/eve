// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"fmt"

	dg "github.com/lf-edge/eve-libs/depgraph"
)

// VIF : virtual interface connecting an application to a network instance.
// It is an external item created by the hypervisor.
type VIF struct {
	// IfName : name of the interface inside the network stack.
	IfName string
	// NetAdapterName is the logical name for this interface received from the controller
	// in NetworkAdapter.Name.
	// Unique in the scope of the application.
	NetAdapterName string
	// MasterIfName : name of the master interface under which this VIF is enslaved.
	// Empty if not enslaved.
	MasterIfName string
}

// Name returns the physical interface name.
func (v VIF) Name() string {
	return v.IfName
}

// Label returns the logical label from NetworkAdapter.
func (v VIF) Label() string {
	return v.NetAdapterName
}

// Type of the item.
func (v VIF) Type() string {
	return VIFTypename
}

// Equal compares two VIF instances.
func (v VIF) Equal(other dg.Item) bool {
	v2, isVIF := other.(VIF)
	if !isVIF {
		return false
	}
	return v == v2
}

// External returns true - VIFs are created by the hypervisor.
func (v VIF) External() bool {
	return true
}

// String describes VIF.
func (v VIF) String() string {
	return fmt.Sprintf("VIF: {ifName: %s, netAdapterName: %s, masterIfName: %s}",
		v.IfName, v.NetAdapterName, v.MasterIfName)
}

// Dependencies returns nothing (external item).
func (v VIF) Dependencies() (deps []dg.Dependency) {
	return nil
}
