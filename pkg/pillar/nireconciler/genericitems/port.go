// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"fmt"
	"net"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

// Port : network port used by network instance for connectivity to outside networks.
type Port struct {
	// IfName : name of the interface inside the network stack.
	IfName string
	// LogicalLabel used to reference this network port.
	LogicalLabel string
	// MasterIfName : name of the master interface under which this port is enslaved.
	// Only used for ports of L2 network instances.
	MasterIfName string
	// AdminUp is true if interface is administratively enabled.
	AdminUp bool
	// IPAddresses : IP addresses assigned to the port.
	IPAddresses []*net.IPNet
}

// Name returns the physical interface name.
func (p Port) Name() string {
	return p.IfName
}

// Label returns the logical label.
func (p Port) Label() string {
	return p.LogicalLabel
}

// Type of the item.
func (p Port) Type() string {
	return PortTypename
}

// Equal compares two Port instances.
func (p Port) Equal(other dg.Item) bool {
	p2, isPort := other.(Port)
	if !isPort {
		return false
	}
	return p.IfName == p2.IfName &&
		p.LogicalLabel == p2.LogicalLabel &&
		p.MasterIfName == p2.MasterIfName &&
		p.AdminUp == p2.AdminUp &&
		generics.EqualSetsFn(p.IPAddresses, p2.IPAddresses, netutils.EqualIPNets)
}

// External returns true - ports are hardware NICs, i.e. not created or managed
// by zedrouter.
func (p Port) External() bool {
	return true
}

// String describes Port.
func (p Port) String() string {
	return fmt.Sprintf("Port: {ifName: %s, logicalLabel: %s, "+
		"masterIfName: %s, adminUP: %t, ipAddresses: %v}", p.IfName, p.LogicalLabel,
		p.MasterIfName, p.AdminUp, p.IPAddresses)
}

// Dependencies returns nothing (external item).
func (p Port) Dependencies() (deps []dg.Dependency) {
	return nil
}

// GetAssignedIPs returns IP addresses assigned to the port.
// The function is needed for the definition of dependencies for
// dnsmasq and HTTP server.
func (p Port) GetAssignedIPs() []*net.IPNet {
	return p.IPAddresses
}
