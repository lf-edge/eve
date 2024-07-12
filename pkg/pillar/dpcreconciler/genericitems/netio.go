// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
)

// IOUsage : how is network IO being used.
type IOUsage uint8

const (
	// IOUsageUnspecified : not specified how the network IO is being used.
	IOUsageUnspecified IOUsage = iota
	// IOUsageL3Adapter : network IO is used as L3 adapter.
	IOUsageL3Adapter
	// IOUsageVlanParent : network IO is used as VLAN parent interface.
	IOUsageVlanParent
	// IOUsageBondAggrIf : network IO is aggregated by Bond interface.
	IOUsageBondAggrIf
)

// NetIO : network IO device.
// External item used to represent a presence of a NIC (or lack of it).
type NetIO struct {
	// LogicalLabel : interface name used by the controller.
	LogicalLabel string
	// IfName : Interface name assigned by the OS.
	IfName string
}

// Name returns the interface name.
func (n NetIO) Name() string {
	return n.IfName
}

// Label returns the logical label.
func (n NetIO) Label() string {
	return n.LogicalLabel + " (IO)"
}

// Type of the item.
func (n NetIO) Type() string {
	return NetIOTypename
}

// Equal is a comparison method for two equally-named NetIO instances.
// It is NOOP, no attributes to compare.
func (n NetIO) Equal(depgraph.Item) bool {
	return true
}

// External returns true because we learn about a presence of a network IO device
// through the NetworkMonitor.
func (n NetIO) External() bool {
	return true
}

// String describes the network IO device.
func (n NetIO) String() string {
	return fmt.Sprintf("Network IO device: %#+v", n)
}

// Dependencies returns nothing (external item).
func (n NetIO) Dependencies() (deps []depgraph.Dependency) {
	return nil
}
