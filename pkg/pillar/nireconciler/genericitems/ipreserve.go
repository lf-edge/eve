// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	"net"

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils"
)

// IPReserve : an item representing allocation and use of an IP address (for bridge).
// The purpose of this item is to ensure that the same IP address will not be
// used by multiple bridges at the same time (incl. inside intermediate reconciliation
// states).
// This works by having the bridge depending on the reservation and by requesting
// re-creation of IPReserve when it changes, thus triggering re-create of bridges
// and all higher-layers items that depend on it.
type IPReserve struct {
	// AddrWithMask : IP address including mask of the subnet to which it belongs.
	AddrWithMask *net.IPNet
	// NetIf : network interface to which the IP address is assigned.
	NetIf NetworkIf
}

// Name returns the IP address in the string format.
func (ip IPReserve) Name() string {
	return ip.AddrWithMask.IP.String()
}

// Label returns the IP address including the mask in the string format.
func (ip IPReserve) Label() string {
	return ip.AddrWithMask.String()
}

// Type of the item.
func (ip IPReserve) Type() string {
	return IPReserveTypename
}

// Equal compares two IP reservations.
func (ip IPReserve) Equal(other dg.Item) bool {
	ip2, isIPReserve := other.(IPReserve)
	if !isIPReserve {
		return false
	}
	return ip.NetIf == ip2.NetIf &&
		utils.EqualIPNets(ip.AddrWithMask, ip2.AddrWithMask)
}

// External returns false - not used for IPs assigned by NIM.
func (ip IPReserve) External() bool {
	return false
}

// String describes IP reservation.
func (ip IPReserve) String() string {
	return fmt.Sprintf("IPReserve: {ifName: %s, address: %s}",
		ip.NetIf.IfName, ip.AddrWithMask.String())
}

// Dependencies returns empty slice.
func (ip IPReserve) Dependencies() (deps []dg.Dependency) {
	return nil
}

// IPReserveConfigurator implements Configurator interface (libs/reconciler)
// for IPReserve.
type IPReserveConfigurator struct {
	Log *base.LogObject
}

// Create is NOOP - IPReserve is not an actual config item, it is used only for
// dependency purposes (to avoid duplicate use of the same IP address).
func (c *IPReserveConfigurator) Create(ctx context.Context, item dg.Item) error {
	return nil
}

// Modify is not implemented.
func (c *IPReserveConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete is NOOP.
func (c *IPReserveConfigurator) Delete(ctx context.Context, item dg.Item) error {
	return nil
}

// NeedsRecreate returns true - change in IPReserve.NetIf usage intentionally triggers
// recreate which cascades to the bridge and other dependent higher-layer items.
func (c *IPReserveConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
