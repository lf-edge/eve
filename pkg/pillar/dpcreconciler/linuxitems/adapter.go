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
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
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
	// UsedAsVlanParent indicates whether the adapter is used as a VLAN parent.
	UsedAsVlanParent bool
	// DhcpType is used to determine the method used to obtain IP address for the network
	// adapter.
	DhcpType types.DhcpType
	// MTU : Maximum transmission unit size.
	MTU uint16
	// StaticIPs : IP addresses assigned to the adapter statically.
	StaticIPs []*net.IPNet
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
		a.WirelessType == a2.WirelessType &&
		a.UsedAsVlanParent == a2.UsedAsVlanParent &&
		a.DhcpType == a2.DhcpType &&
		a.MTU == a2.MTU &&
		generics.EqualSetsFn(a.StaticIPs, a2.StaticIPs, netutils.EqualIPNets)
}

// External returns false.
func (a Adapter) External() bool {
	return false
}

// String describes network adapter.
func (a Adapter) String() string {
	return fmt.Sprintf("Network Adapter: %#+v", a)
}

// Dependencies returns the underlying lower-layer adapter as the dependency
// (unless this is physical interface at the lowest layer).
// For WiFi we additionally require that rfkill for wlan is unblocked first
// (otherwise LinkSetUp and other netlink calls will fail).
func (a Adapter) Dependencies() (deps []depgraph.Dependency) {
	// Dependency 1: underlying lower-layer adapter must exist.
	var depType string
	var mustSatisfy func(item depgraph.Item) bool
	switch a.L2Type {
	case types.L2LinkTypeNone:
		// Attached directly to a physical interface.
		// In this case the interface has to be "allocated" for use with an adapter.
		depType = genericitems.PhysIfTypename
		mustSatisfy = func(item depgraph.Item) bool {
			physIf := item.(PhysIf)
			return physIf.Usage == genericitems.IOUsageAdapter
		}
	case types.L2LinkTypeVLAN:
		depType = genericitems.VlanTypename
	case types.L2LinkTypeBond:
		depType = genericitems.BondTypename
	}
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: depType,
			ItemName: a.IfName,
		},
		MustSatisfy: mustSatisfy,
		Description: "Underlying network interface must exist",
	})
	// Dependency 2: WiFi requires rfkill unblock to be performed first.
	if a.WirelessType == types.WirelessTypeWifi {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.Reference(Wlan{}),
			MustSatisfy: func(item depgraph.Item) bool {
				wlan, isWlan := item.(Wlan)
				if !isWlan {
					// unreachable
					return false
				}
				return wlan.EnableRF
			},
			Description: "radio transmission must be enabled",
		})
	}
	return deps
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
	if adapter.WirelessType == types.WirelessTypeCellular {
		// Managed by the wwan microservice, nothing to do here.
		return nil
	}
	if !c.isAdapterBridgedByNIM(adapter) {
		// Make sure that the interface is UP.
		if err := netlink.LinkSetUp(link); err != nil {
			err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v",
				adapter.IfName, err)
			c.Log.Error(err)
			return err
		}
		// Do not proceed with bridging the adapter, just set the MTU and static IPs.
		err = c.setAdapterMTU(adapter, link)
		if err != nil {
			return err
		}
		return c.updateAdapterStaticIPs(link, adapter.StaticIPs, nil)
	}
	kernIfname := "k" + adapter.IfName
	_, err = netlink.LinkByName(kernIfname)
	if err == nil {
		err = fmt.Errorf("interface %s already exists",
			kernIfname)
		c.Log.Error(err)
		return err
	}
	// Make sure the ethernet interface is DOWN before renaming
	// and changing the MAC address, otherwise we get error
	// `Device or resource busy`.
	if err := netlink.LinkSetDown(link); err != nil {
		err = fmt.Errorf("netlink.LinkSetDown(%s) failed: %v",
			adapter.IfName, err)
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
	// Make sure that corresponding bridge and interface are UP right
	// after MAC address assignment and interface rename. Order matters,
	// otherwise host returns `Device or resource busy`.
	if err := netlink.LinkSetUp(bridge); err != nil {
		err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v",
			adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	if err := netlink.LinkSetUp(kernLink); err != nil {
		err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v",
			kernIfname, err)
		c.Log.Error(err)
		return err
	}
	// Finally, assign statically configured IPs.
	return c.updateAdapterStaticIPs(bridge, adapter.StaticIPs, nil)
}

// Return true if NIM is responsible for creating a Linux bridge for the adapter.
// Bridge is NOT created by NIM if:
//   - the adapter is wireless: it is not valid to put wireless adapter under a bridge,
//   - or if the adapter is configured with DHCP passthrough AND has no VLAN sub-interfaces
//     attached: in that case, NIM does not have to apply IP config, create sub-interfaces
//     or test connectivity, and it can leave it up to zedrouter to bridge the port with
//     applications (and possibly also with other ports) if requested by the user
func (c *AdapterConfigurator) isAdapterBridgedByNIM(adapter Adapter) bool {
	return adapter.WirelessType == types.WirelessTypeNone &&
		(adapter.DhcpType == types.DhcpTypeClient ||
			adapter.DhcpType == types.DhcpTypeStatic ||
			adapter.UsedAsVlanParent)
}

func (c *AdapterConfigurator) setAdapterMTU(adapter Adapter, link netlink.Link) error {
	mtu := adapter.GetMTU()
	if link.Attrs().MTU != int(mtu) {
		err := netlink.LinkSetMTU(link, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for adapter %s: %w",
				mtu, adapter.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

func (c *AdapterConfigurator) updateAdapterStaticIPs(link netlink.Link,
	newIPs, prevIPs []*net.IPNet) error {
	newIPs, obsoleteIPs := generics.DiffSetsFn(newIPs, prevIPs, netutils.EqualIPNets)
	for _, ipNet := range obsoleteIPs {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrDel(link, addr); err != nil {
			err = fmt.Errorf("failed to del addr %v from adapter %s: %v",
				ipNet, link.Attrs().Name, err)
			c.Log.Error(err)
			return err
		}
	}
	for _, ipNet := range newIPs {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrAdd(link, addr); err != nil {
			err = fmt.Errorf("failed to add addr %v to adapter %s: %v",
				ipNet, link.Attrs().Name, err)
			c.Log.Error(err)
			return err
		}
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

// Modify is able to update the MTU attribute and the set of static IPs.
func (c *AdapterConfigurator) Modify(_ context.Context, oldItem, newItem depgraph.Item) (err error) {
	oldAdapter, isAdapter := oldItem.(Adapter)
	if !isAdapter {
		return fmt.Errorf("invalid item type %T, expected Adapter", newItem)
	}
	adapter, isAdapter := newItem.(Adapter)
	if !isAdapter {
		return fmt.Errorf("invalid item type %T, expected Adapter", newItem)
	}
	if adapter.WirelessType == types.WirelessTypeCellular {
		// Managed by the wwan microservice, nothing to do here.
		return nil
	}
	adapterLink, err := netlink.LinkByName(adapter.IfName)
	if err != nil {
		err = fmt.Errorf("failed to get adapter %s link: %v", adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	err = c.setAdapterMTU(adapter, adapterLink)
	if err != nil {
		return err
	}
	return c.updateAdapterStaticIPs(adapterLink, adapter.StaticIPs, oldAdapter.StaticIPs)
}

// Delete undoes Create - i.e. moves MAC address and ifName back to the interface
// and removes the bridge.
func (c *AdapterConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	adapter := item.(Adapter)
	// First, remove all statically assigned IPs.
	adapterLink, err := netlink.LinkByName(adapter.IfName)
	if err != nil {
		err = fmt.Errorf("failed to get adapter %s link: %v", adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	err = c.updateAdapterStaticIPs(adapterLink, nil, adapter.StaticIPs)
	if err != nil {
		return err
	}
	if !c.isAdapterBridgedByNIM(adapter) {
		// Adapter is not bridged by NIM, nothing else to undo here.
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
	// Delete the bridge interface.
	if err := netlink.LinkDel(adapterLink); err != nil {
		err = fmt.Errorf("netlink.LinkDel(%s) failed: %v",
			adapter.IfName, err)
		c.Log.Error(err)
		return err
	}
	// Make sure the ethernet interface is DOWN before renaming
	// and changing the MAC address, otherwise we get error
	// `Device or resource busy`.
	if err := netlink.LinkSetDown(kernLink); err != nil {
		err = fmt.Errorf("netlink.LinkSetDown(%s) failed: %v",
			kernIfname, err)
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
// On the other hand, Modify is able to update the MTU attribute and the set of static IPs.
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
	return oldCfg.L2Type != newCfg.L2Type ||
		oldCfg.WirelessType != newCfg.WirelessType ||
		oldCfg.DhcpType != newCfg.DhcpType ||
		// There is no need to re-create the adapter when VLANs are added or removed,
		// as long as the bridge continues to be managed by the same microservice
		// (NIM or zedrouter).
		// For this reason, we do not compare UsedAsVlanParent directly and instead
		// only check whether the adapter’s bridge ownership (isAdapterBridgedByNIM)
		// has changed.
		c.isAdapterBridgedByNIM(oldCfg) != c.isAdapterBridgedByNIM(newCfg)
}
