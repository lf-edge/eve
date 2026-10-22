// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"bytes"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
)

// PhysIf : physical network interface.
// External item used to represent a presence (or lack) of a NIC.
type PhysIf struct {
	// MAC address assigned by Evetest.
	MAC net.HardwareAddr
	// LogicalLabel : label used within the network model.
	LogicalLabel string
}

// Name returns the name of the physical interface item.
func (p PhysIf) Name() string {
	return p.MAC.String()
}

// Label returns the label of the physical interface item.
func (p PhysIf) Label() string {
	return p.LogicalLabel
}

// Type returns the typename of the physical interface item.
func (p PhysIf) Type() string {
	return PhysIfTypename
}

func equalPhysIfs(p1, p2 PhysIf) bool {
	return p1.LogicalLabel == p2.LogicalLabel &&
		bytes.Equal(p1.MAC, p2.MAC)
}

// Equal is a comparison method for two PhysIf instances.
func (p PhysIf) Equal(other depgraph.Item) bool {
	p2, isPhysIf := other.(PhysIf)
	if !isPhysIf {
		return false
	}
	return equalPhysIfs(p, p2)
}

// External returns true because we learn about a presence of a physical interface
// through netlink API.
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
