// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
)

// PhysIf : physical network interface.
// External item used to represent a presence (or lack of it) of a NIC.
type PhysIf struct {
	// LogicalLabel : interface name used by the controller.
	LogicalLabel string
	// IfName : Interface name assigned by the OS.
	IfName string
}

// Name returns the physical interface name.
func (p PhysIf) Name() string {
	return p.IfName
}

// Label returns the logical label.
func (p PhysIf) Label() string {
	return p.LogicalLabel
}

// Type of the item.
func (p PhysIf) Type() string {
	return PhysIfTypename
}

// Equal is a comparison method for two equally-named PhysIf instances.
// It is NOOP, no attributes to compare.
func (p PhysIf) Equal(depgraph.Item) bool {
	return true
}

// External returns true because we learn about a presence of a physical interface
// through the NetworkMonitor.
func (p PhysIf) External() bool {
	return true
}

// String describes the interface.
func (p PhysIf) String() string {
	return fmt.Sprintf("Physical Network Interface: %#+v", p)
}

// Dependencies returns nothing (external item).
func (p PhysIf) Dependencies() (deps []depgraph.Dependency) {
	return nil
}
