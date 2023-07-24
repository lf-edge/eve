// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

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
	return a.L2Type == a2.L2Type
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
		depType = genericitems.IOHandleTypename
		mustSatisfy = func(item depgraph.Item) bool {
			ioHandle := item.(genericitems.IOHandle)
			return ioHandle.Usage == genericitems.IOUsageL3Adapter
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
	if !c.createBridge(adapter.IfName) {
		// Do not put the interface under a bridge.
		// Just make sure that the interface is UP.
		c.Log.Noticef("Not creating bridge for interface: %s, link type: %s",
			adapter.IfName, link.Type())
		if err := netlink.LinkSetUp(link); err != nil {
			err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v",
				adapter.IfName, err)
			c.Log.Error(err)
			return err
		}
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

func (c *AdapterConfigurator) createBridge(ifName string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/wireless", ifName))
	if err == nil || strings.HasPrefix(ifName, "wwan") {
		// Do not put wireless interface under a bridge.
		return false
	}
	return true
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

// Modify is not implemented.
func (c *AdapterConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete undoes Create - i.e. moves MAC address and ifName back to the interface
// and removes the bridge.
func (c *AdapterConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	adapter := item.(Adapter)
	if !c.createBridge(adapter.IfName) {
		// nothing to undo
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

// NeedsRecreate returns true - Modify is not implemented.
func (c *AdapterConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
