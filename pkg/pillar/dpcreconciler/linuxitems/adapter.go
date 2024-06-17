// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// Adapter : Network adapter (in the EVE's API also known as SystemAdapter).
type Adapter struct {
	// LogicalLabel : Note that the adapter and the underlying interface share
	// the same logical label. Inside EVE both are wrapped by a single NetworkPortConfig.
	LogicalLabel string
	// IfName : Name of the interface (as assigned by the OS) to which the adapter
	// is attached.
	IfName string
	// L2Type : link type of the underlying interface.
	// L2LinkTypeNone is used if adapter is directly attached to a physical interface.
	L2Type types.L2LinkType
	// WirelessType is used to distinguish between Ethernet, WiFi and cellular port.
	WirelessType types.WirelessType
	// MTU : Maximum transmission unit size.
	MTU uint16
}

// Name uses the interface name to identify the adapter.
func (a Adapter) Name() string {
	return a.IfName
}

// Label returns the logical label.
func (a Adapter) Label() string {
	return a.LogicalLabel + " (adapter)"
}

// Type of the item.
func (a Adapter) Type() string {
	return genericitems.AdapterTypename
}

// Equal is a comparison method for two equally-named adapter instances.
func (a Adapter) Equal(other depgraph.Item) bool {
	a2 := other.(Adapter)
	return a.L2Type == a2.L2Type &&
		a.WirelessType == a.WirelessType &&
		a.MTU == a2.MTU
}

// External returns false.
func (a Adapter) External() bool {
	return false
}

// String describes network adapter.
func (a Adapter) String() string {
	return fmt.Sprintf("Network Adapter: %#+v", a)
}

// Dependencies returns underlying lower-layer adapter as the dependency
// (unless this is physical interface at the lowest layer).
func (a Adapter) Dependencies() (deps []depgraph.Dependency) {
	var depType string
	var mustSatisfy func(item depgraph.Item) bool
	switch a.L2Type {
	case types.L2LinkTypeNone:
		// Attached directly to a physical interface.
		// In this case the interface has to be "allocated" for use as an L3 adapter.
		depType = genericitems.PhysIfTypename
		mustSatisfy = func(item depgraph.Item) bool {
			physIf := item.(PhysIf)
			return physIf.Usage == genericitems.IOUsageL3Adapter
		}
	case types.L2LinkTypeVLAN:
		depType = genericitems.VlanTypename
	case types.L2LinkTypeBond:
		depType = genericitems.BondTypename
	}
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: depType,
				ItemName: a.IfName,
			},
			MustSatisfy: mustSatisfy,
			Description: "Underlying network interface must exist",
		},
	}
}

// GetMTU returns MTU configured for the Adapter (applied to bridge).
func (a Adapter) GetMTU() uint16 {
	if a.MTU == 0 {
		return types.DefaultMTU
	}
	return a.MTU
}

// AdapterConfigurator implements Configurator interface (libs/reconciler) for network adapters.
type AdapterConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create creates a bridge, makes the interface its slave and moves ifName and MAC
// address of the interface to this bridge.
func (c *AdapterConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	adapter := item.(Adapter)
	link, err := netlink.LinkByName(adapter.IfName)
	if err != nil {
		// Adapter.Dependencies() will prevent this.
		err = fmt.Errorf("netlink.LinkByName(%s) failed: %v",
			adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	switch adapter.WirelessType {
	case types.WirelessTypeNone:
		// Continue below to put the Ethernet interface under a bridge.
		break
	case types.WirelessTypeWifi:
		// Do not put the WiFi interface under a bridge.
		// Just make sure that the interface is UP.
		if err := netlink.LinkSetUp(link); err != nil {
			err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v",
				adapter.IfName, err)
			c.Log.Error(err)
			return err
		}
		return nil
	case types.WirelessTypeCellular:
		// Managed by the wwan microservice, nothing to do here.
		return nil
	}
	kernIfname := "k" + adapter.IfName
	_, err = netlink.LinkByName(kernIfname)
	if err == nil {
		err = fmt.Errorf("interface %s already exists",
			kernIfname)
		c.Log.Error(err)
		return err
	}
	// Get MAC address and create the alternate with the group bit toggled.
	macAddr := link.Attrs().HardwareAddr
	altMacAddr := c.alternativeMAC(link.Attrs().HardwareAddr)
	if len(altMacAddr) != 0 {
		// Toggle MAC address - set to altMacAddr
		if err := netlink.LinkSetHardwareAddr(link, altMacAddr); err != nil {
			err = fmt.Errorf("netlink.LinkSetHardwareAddr(%s, %s) failed: %v",
				adapter.IfName, altMacAddr, err)
			c.Log.Error(err)
			return err
		}
	}
	if err := types.IfRename(c.Log, adapter.IfName, kernIfname); err != nil {
		err = fmt.Errorf("IfRename(%s, %s) failed: %v",
			adapter.IfName, kernIfname, err)
		c.Log.Error(err)
		return err
	}
	// Create bridge and name it ethN, use macAddr.
	attrs := netlink.NewLinkAttrs()
	attrs.Name = adapter.IfName
	attrs.HardwareAddr = macAddr
	attrs.MTU = int(adapter.GetMTU())
	bridge := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(bridge); err != nil {
		err = fmt.Errorf("netlink.LinkAdd(%s) failed: %v",
			adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	// Look up again after rename
	kernLink, err := netlink.LinkByName(kernIfname)
	if err != nil {
		err = fmt.Errorf("netlink.LinkByName(%s) failed: %v",
			kernIfname, err)
		c.Log.Error(err)
		return err
	}
	// ip link set kethN master ethN
	if err := netlink.LinkSetMaster(kernLink, bridge); err != nil {
		err = fmt.Errorf("netlink.LinkSetMaster(%s, %s) failed: %v",
			kernIfname, adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	if err := netlink.LinkSetUp(bridge); err != nil {
		err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v",
			adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Create alternate MAC address with the group bit toggled.
func (c *AdapterConfigurator) alternativeMAC(mac net.HardwareAddr) net.HardwareAddr {
	var altMacAddr net.HardwareAddr
	if len(mac) != 0 {
		altMacAddr = make([]byte, len(mac))
		copy(altMacAddr, mac)
		altMacAddr[0] = altMacAddr[0] ^ 2
	}
	return altMacAddr
}

// Modify is able to update the MTU attribute.
func (c *AdapterConfigurator) Modify(_ context.Context, _, newItem depgraph.Item) (err error) {
	adapter, isAdapter := newItem.(Adapter)
	if !isAdapter {
		return fmt.Errorf("invalid item type %T, expected Adapter", newItem)
	}
	if adapter.WirelessType != types.WirelessTypeNone {
		// wireless port, nothing to do here
		return nil
	}
	adapterLink, err := netlink.LinkByName(adapter.IfName)
	if err != nil {
		err = fmt.Errorf("failed to get adapter %s link: %v", adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	mtu := adapter.GetMTU()
	if adapterLink.Attrs().MTU != int(mtu) {
		err = netlink.LinkSetMTU(adapterLink, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for adapter %s: %w",
				mtu, adapter.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Delete undoes Create - i.e. moves MAC address and ifName back to the interface
// and removes the bridge.
func (c *AdapterConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	adapter := item.(Adapter)
	if adapter.WirelessType != types.WirelessTypeNone {
		// wireless port, nothing to do here
		return nil
	}
	// After removing/renaming interfaces it is best to clear the cache.
	defer c.NetworkMonitor.ClearCache()
	kernIfname := "k" + adapter.IfName
	kernLink, err := netlink.LinkByName(kernIfname)
	if err != nil {
		err = fmt.Errorf("netlink.LinkByName(%s) failed: %v",
			kernIfname, err)
		c.Log.Error(err)
		return err
	}
	// ip link set kethN nomaster
	if err := netlink.LinkSetNoMaster(kernLink); err != nil {
		err = fmt.Errorf("netlink.LinkSetNoMaster(%s) failed: %v",
			kernIfname, err)
		c.Log.Error(err)
		return err
	}
	// delete bridge link
	attrs := netlink.NewLinkAttrs()
	attrs.Name = adapter.IfName
	bridge := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkDel(bridge); err != nil {
		err = fmt.Errorf("netlink.LinkDel(%s) failed: %v",
			adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	// Toggle MAC address of the interface back to the original.
	altMacAddr := c.alternativeMAC(kernLink.Attrs().HardwareAddr)
	if len(altMacAddr) != 0 {
		if err := netlink.LinkSetHardwareAddr(kernLink, altMacAddr); err != nil {
			err = fmt.Errorf("netlink.LinkSetHardwareAddr(%s, %s) failed: %v",
				kernIfname, altMacAddr, err)
			c.Log.Error(err)
			return err
		}
	}
	// Rename the interface back to the original name.
	if err := types.IfRename(c.Log, kernIfname, adapter.IfName); err != nil {
		err = fmt.Errorf("IfRename(%s, %s) failed: %v",
			kernIfname, adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true if L2Type or WirelessType have changed.
// On the other hand, Modify is able to update the MTU attribute.
func (c *AdapterConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldCfg, isAdapter := oldItem.(Adapter)
	if !isAdapter {
		// unreachable
		return false
	}
	newCfg, isAdapter := newItem.(Adapter)
	if !isAdapter {
		// unreachable
		return false
	}
	return oldCfg.L2Type != newCfg.L2Type || oldCfg.WirelessType != newCfg.WirelessType
}
