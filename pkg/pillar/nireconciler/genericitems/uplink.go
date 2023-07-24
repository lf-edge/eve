// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"fmt"
	"net"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/utils"
)

// Uplink : uplink interface used by network instance for connectivity to outside networks.
type Uplink struct {
	// IfName : name of the interface inside the network stack.
	IfName string
	// LogicalLabel used to reference this uplink interface.
	LogicalLabel string
	// MasterIfName : name of the master interface under which this Uplink is enslaved.
	// Only used for uplinks of L2 network instances.
	MasterIfName string
	// AdminUp is true if interface is administratively enabled.
	AdminUp bool
	// IPAddresses : IP addresses assigned to the uplink interface.
	IPAddresses []*net.IPNet
}

// Name returns the physical interface name.
func (u Uplink) Name() string {
	return u.IfName
}

// Label returns the logical label.
func (u Uplink) Label() string {
	return u.LogicalLabel
}

// Type of the item.
func (u Uplink) Type() string {
	return UplinkTypename
}

// Equal compares two Uplink instances.
func (u Uplink) Equal(other dg.Item) bool {
	u2, isUplink := other.(Uplink)
	if !isUplink {
		return false
	}
	return u.IfName == u2.IfName &&
		u.LogicalLabel == u2.LogicalLabel &&
		u.MasterIfName == u2.MasterIfName &&
		u.AdminUp == u2.AdminUp &&
		utils.EqualSetsFn(u.IPAddresses, u2.IPAddresses, utils.EqualIPNets)
}

// External returns true - uplinks are physical interfaces, i.e. not created by zedrouter.
func (u Uplink) External() bool {
	return true
}

// String describes Uplink.
func (u Uplink) String() string {
	return fmt.Sprintf("Uplink: {ifName: %s, logicalLabel: %s, "+
		"masterIfName: %s, adminUP: %t, ipAddresses: %v}", u.IfName, u.LogicalLabel,
		u.MasterIfName, u.AdminUp, u.IPAddresses)
}

// Dependencies returns nothing (external item).
func (u Uplink) Dependencies() (deps []dg.Dependency) {
	return nil
}

// GetAssignedIPs returns IP addresses assigned to the uplink interface.
// The function is needed for the definition of dependencies for
// dnsmasq and HTTP server.
func (u Uplink) GetAssignedIPs() []*net.IPNet {
	return u.IPAddresses
}
