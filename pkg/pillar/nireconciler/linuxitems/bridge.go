// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/vishvananda/netlink"
)

// Bridge : Linux bridge.
type Bridge struct {
	// IfName : name of the bridge interface inside the network stack.
	IfName string
	// CreatedByNIM : true if this bridge was created by NIM to extend the bridge domain
	// of an uplink interface. Such bridge is then directly used for L2 network instances.
	CreatedByNIM bool
	// MACAddress : MAC address allocated for (or already assigned by NIM to) the bridge.
	MACAddress net.HardwareAddr
	// IPAddresses : a set of IP addresses allocated for the bridge itself (L3 NI),
	// or already assigned by the DHCP client (NIM-created bridge, L2 NI).
	IPAddresses []*net.IPNet
}

// Name returns the physical interface name.
func (b Bridge) Name() string {
	return b.IfName
}

// Label is not provided.
func (b Bridge) Label() string {
	return ""
}

// Type of the item.
func (b Bridge) Type() string {
	return BridgeTypename
}

// Equal compares two Bridge instances.
func (b Bridge) Equal(other dg.Item) bool {
	b2, isBridge := other.(Bridge)
	if !isBridge {
		return false
	}
	return b.IfName == b2.IfName &&
		b.CreatedByNIM == b2.CreatedByNIM &&
		bytes.Equal(b.MACAddress, b2.MACAddress) &&
		utils.EqualSetsFn(b.IPAddresses, b2.IPAddresses, utils.EqualIPNets)
}

// External returns true if it was created by NIM and not be zedrouter.
func (b Bridge) External() bool {
	return b.CreatedByNIM
}

// String describes Bridge.
func (b Bridge) String() string {
	return fmt.Sprintf("Bridge: {ifName: %s, createdByNIM: %t, "+
		"macAddress: %s, ipAddresses: %v}", b.IfName, b.CreatedByNIM,
		b.MACAddress, b.IPAddresses)
}

// Dependencies returns reservations of IPs that bridge should have assigned.
func (b Bridge) Dependencies() (deps []dg.Dependency) {
	if b.External() {
		return nil
	}
	for _, ip := range b.IPAddresses {
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.Reference(genericitems.IPReserve{AddrWithMask: ip}),
			Description:  "IP address must be reserved for the bridge",
			MustSatisfy: func(item dg.Item) bool {
				ipReserve, isIPReserve := item.(genericitems.IPReserve)
				if !isIPReserve {
					// Should be unreachable.
					return false
				}
				return ipReserve.NetIf.ItemRef == dg.Reference(b)
			},
		})
	}
	return deps
}

// GetAssignedIPs returns IP addresses assigned to the bridge interface.
// The function is needed for the definition of dependencies for
// dnsmasq and HTTP server.
func (b Bridge) GetAssignedIPs() []*net.IPNet {
	return b.IPAddresses
}

// BridgeConfigurator implements Configurator interface (libs/reconciler) for Linux bridge.
type BridgeConfigurator struct {
	Log *base.LogObject
}

// Create adds new Linux bridge.
func (c *BridgeConfigurator) Create(ctx context.Context, item dg.Item) error {
	bridge, isBridge := item.(Bridge)
	if !isBridge {
		return fmt.Errorf("invalid item type %T, expected Bridge", item)
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridge.IfName
	if len(bridge.MACAddress) > 0 {
		attrs.HardwareAddr = bridge.MACAddress
	}
	netlinkBridge := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(netlinkBridge); err != nil {
		err = fmt.Errorf("failed to add bridge %s: %w", bridge.IfName, err)
		c.Log.Error(err)
		return err
	}
	if err := netlink.LinkSetUp(netlinkBridge); err != nil {
		err = fmt.Errorf("failed to set bridge %s UP: %w", bridge.IfName, err)
		c.Log.Error(err)
		return err
	}
	// Disable ICMP redirects.
	sysctlSetting := fmt.Sprintf("net.ipv4.conf.%s.send_redirects=0", bridge.IfName)
	args := []string{"-w", sysctlSetting}
	out, err := base.Exec(c.Log, "sysctl", args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("failed to disable ICMP redirects for bridge %s, "+
			"output from sysctl with args %v: %s", bridge.IfName, args, out)
		c.Log.Error(err)
		return err
	}
	// Assign IP addresses.
	link, err := netlink.LinkByName(bridge.IfName)
	if err != nil {
		err = fmt.Errorf("failed to get link for bridge %s: %w", bridge.IfName, err)
		c.Log.Error(err)
		return err
	}
	for _, ipAddr := range bridge.IPAddresses {
		addr := &netlink.Addr{IPNet: ipAddr}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add IP address %v to bridge %s: %w",
				ipAddr, bridge.IfName, err)
		}
	}
	return nil
}

// Modify is not implemented.
func (c *BridgeConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes Linux bridge.
func (c *BridgeConfigurator) Delete(ctx context.Context, item dg.Item) error {
	bridge, isBridge := item.(Bridge)
	if !isBridge {
		return fmt.Errorf("invalid item type %T, expected Bridge", item)
	}
	link, err := netlink.LinkByName(bridge.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select bridge %s for removal: %w",
			bridge.IfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkDel(link)
	if err != nil {
		err = fmt.Errorf("failed to delete bridge %s: %w", bridge.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *BridgeConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
