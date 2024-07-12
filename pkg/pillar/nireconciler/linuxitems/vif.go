// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/vishvananda/netlink"
)

// VIF : virtual interface connecting an application to a network instance.
// It can be either an external item created by the hypervisor,
// or an internal item configured by zedrouter.
type VIF struct {
	// HostIfName : name of the interface inside the network stack on the host side.
	HostIfName string
	// NetAdapterName is the logical name for this interface received from the controller
	// in NetworkAdapter.Name.
	// Unique in the scope of the application.
	NetAdapterName string
	// Variant : VIF should be one of the supported variants.
	Variant VIFVariant
}

// VIFVariant is like union, only one option should have non-zero value.
type VIFVariant struct {
	// Enable if VIF is created by an external process (e.g. hypervisor).
	External bool
	// Veth configured by zedrouter between the host and the app (container).
	Veth Veth
}

// Veth : virtual ethernet pair created between the host and the (container) app
// network namespace.
type Veth struct {
	ForApp ContainerApp
	// AppIfName : name of the interface inside the network stack on the app side.
	AppIfName string
	// AppIfMAC : MAC address assigned to the Veth interface on the app side.
	AppIfMAC net.HardwareAddr
	// AppIPs : IP addresses assigned to Veth on the app side.
	AppIPs []*net.IPNet
	// MTU : Maximum transmission unit size.
	MTU uint16
}

// Name returns the physical interface name on the host side.
func (v VIF) Name() string {
	return v.HostIfName
}

// Label returns the logical label from NetworkAdapter.
func (v VIF) Label() string {
	return v.NetAdapterName
}

// Type of the item.
func (v VIF) Type() string {
	return VIFTypename
}

// Equal compares two VIF instances.
func (v VIF) Equal(other dg.Item) bool {
	v2, isVIF := other.(VIF)
	if !isVIF {
		return false
	}
	return v.HostIfName == v2.HostIfName &&
		v.NetAdapterName == v2.NetAdapterName &&
		v.Variant.External == v2.Variant.External &&
		v.Variant.Veth.ForApp == v2.Variant.Veth.ForApp &&
		v.Variant.Veth.AppIfName == v2.Variant.Veth.AppIfName &&
		v.Variant.Veth.MTU == v2.Variant.Veth.MTU &&
		bytes.Equal(v.Variant.Veth.AppIfMAC, v2.Variant.Veth.AppIfMAC) &&
		generics.EqualSetsFn(v.Variant.Veth.AppIPs, v2.Variant.Veth.AppIPs,
			netutils.EqualIPNets)
}

// External returns true if VIF is created by the hypervisor.
func (v VIF) External() bool {
	return v.Variant.External
}

// String describes VIF.
func (v VIF) String() string {
	if v.External() {
		return fmt.Sprintf(
			"External VIF: {hostIfName: %s, netAdapterName: %s}",
			v.HostIfName, v.NetAdapterName)
	}
	veth := v.Variant.Veth
	return fmt.Sprintf(
		"Veth VIF: {hostIfName: %s, netAdapterName: %s, "+
			"app: %s, appNetNsName: %s, appIfName: %s, appIfMAC: %v, appIPs: %v, MTU: %d",
		v.HostIfName, v.NetAdapterName, veth.ForApp.ID, veth.ForApp.NetNsName,
		veth.AppIfName, veth.AppIfMAC, veth.AppIPs, veth.MTU)
}

// Dependencies returns no dependencies.
func (v VIF) Dependencies() (deps []dg.Dependency) {
	return nil
}

// GetAssignedIPs returns IP addresses assigned (by zedrouter) to the VIF interface.
func (v VIF) GetAssignedIPs() []*net.IPNet {
	if v.External() {
		return nil
	}
	return v.Variant.Veth.AppIPs
}

// GetMTU returns MTU configured for the VIF.
func (v VIF) GetMTU() uint16 {
	if v.External() {
		return 0
	}
	if v.Variant.Veth.MTU == 0 {
		return types.DefaultMTU
	}
	return v.Variant.Veth.MTU
}

// VIFConfigurator implements Configurator interface for Veth VIF.
type VIFConfigurator struct {
	Log *base.LogObject
}

// Create adds new veth.
func (c *VIFConfigurator) Create(ctx context.Context, item dg.Item) error {
	vif, isVif := item.(VIF)
	if !isVif {
		// Should be unreachable.
		return fmt.Errorf("invalid item type %T, expected VIF", item)
	}
	if vif.External() {
		// Should be unreachable.
		return errors.New("invalid VIF variant, expected Veth")
	}
	appPeer := vif.Variant.Veth
	attrs := netlink.NewLinkAttrs()
	attrs.Name = vif.HostIfName
	attrs.MTU = int(vif.GetMTU())
	link := &netlink.Veth{
		LinkAttrs: attrs,
		// TODO: generate temporary interface name to avoid conflicts with the host interfaces.
		PeerName: appPeer.AppIfName,
	}
	err := netlink.LinkAdd(link)
	if err != nil {
		err = fmt.Errorf("failed to add veth %s/%s: %v",
			vif.HostIfName, appPeer.AppIfName, err)
		c.Log.Error(err)
		return err
	}
	defer func() {
		// If the Create operation failed, make sure we do not leave partially created
		// veth behind.
		if err != nil {
			err2 := netlink.LinkDel(link)
			if err2 != nil {
				c.Log.Errorf("failed to revert created veth %s/%s: %v",
					vif.HostIfName, appPeer.AppIfName, err2)
			}
		}
	}()
	err = c.configureVethPeer("", vif.HostIfName, nil, nil)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	err = c.configureVethPeer(appPeer.ForApp.NetNsName, appPeer.AppIfName,
		appPeer.AppIfMAC, appPeer.AppIPs)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *VIFConfigurator) configureVethPeer(
	netNs, ifName string, mac net.HardwareAddr, IPs []*net.IPNet) error {
	// Get the interface link handle.
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link for veth peer %s: %w", ifName, err)
	}
	if netNs != "" {
		// Move interface into the namespace (leave ns with defer).
		err = moveLinkToNamespace(link, netNs)
		if err != nil {
			return fmt.Errorf("failed to move veth peer %s to net namespace %s: %w",
				ifName, netNs, err)
		}
		// Continue configuring veth peer in the target namespace.
		revertNs, err := switchToNamespace(c.Log, netNs)
		if err != nil {
			return fmt.Errorf("failed to switch to net namespace %s: %w", netNs, err)
		}
		defer revertNs()
		// Get link for the peer in this namespace.
		link, err = netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to get link for veth peer %s in ns %s: %w",
				ifName, netNs, err)
		}
	}
	if len(mac) > 0 {
		err = netlink.LinkSetHardwareAddr(link, mac)
		if err != nil {
			return fmt.Errorf("failed to set MAC address %s for veth peer %s: %w",
				mac, ifName, err)
		}
	}
	// Set link UP.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set veth peer %s UP: %v", ifName, err)
	}
	// Assign IP addresses.
	for _, ipNet := range IPs {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add addr %v to veth peer %s: %v",
				ipNet, ifName, err)
		}
	}
	return nil
}

// Modify allows to change assigned IP addresses and MTU.
func (c *VIFConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	oldVif, isVif := oldItem.(VIF)
	if !isVif {
		// Should be unreachable.
		err = fmt.Errorf("invalid item type %T, expected VIF", oldItem)
		c.Log.Error(err)
		return err
	}
	newVif, isVif := newItem.(VIF)
	if !isVif {
		// Should be unreachable.
		err = fmt.Errorf("invalid item type %T, expected VIF", newItem)
		c.Log.Error(err)
		return err
	}
	oldVeth := oldVif.Variant.Veth
	newVeth := newVif.Variant.Veth
	appNetNs := newVeth.ForApp.NetNsName
	hostIfName := newVif.HostIfName
	appIfName := newVeth.AppIfName
	mtu := newVif.GetMTU()
	// If changed, modify MTU of the VETH peer in the host namespace.
	link, err := netlink.LinkByName(hostIfName)
	if err != nil {
		err = fmt.Errorf("failed to get link for veth peer %s in the host ns: %w",
			hostIfName, err)
		c.Log.Error(err)
		return err
	}
	if link.Attrs().MTU != int(mtu) {
		err = netlink.LinkSetMTU(link, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for VIF (Veth) %s: %w",
				mtu, hostIfName, err)
			c.Log.Error(err)
			return err
		}
	}
	// Continue configuring veth peer in the app namespace.
	revertNs, err := switchToNamespace(c.Log, appNetNs)
	if err != nil {
		err = fmt.Errorf("failed to switch to net namespace %s: %w", appNetNs, err)
		c.Log.Error(err)
		return err
	}
	defer revertNs()
	// Get link for the peer in this namespace.
	link, err = netlink.LinkByName(appIfName)
	if err != nil {
		err = fmt.Errorf("failed to get link for veth peer %s in ns %s: %w",
			appIfName, appNetNs, err)
		c.Log.Error(err)
		return err
	}
	obsoleteIPs, newIPs := generics.DiffSetsFn(oldVeth.AppIPs, newVeth.AppIPs,
		netutils.EqualIPNets)
	for _, ipNet := range obsoleteIPs {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrDel(link, addr); err != nil {
			err = fmt.Errorf("failed to del addr %v from veth peer %s: %v",
				ipNet, appIfName, err)
			c.Log.Error(err)
			return err
		}
	}
	for _, ipNet := range newIPs {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrAdd(link, addr); err != nil {
			err = fmt.Errorf("failed to add addr %v to veth peer %s: %v",
				ipNet, appIfName, err)
			c.Log.Error(err)
			return err
		}
	}
	if link.Attrs().MTU != int(mtu) {
		err = netlink.LinkSetMTU(link, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for VIF (Veth) %s: %w",
				mtu, appIfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Delete removes veth.
// Should be enough to just remove one side.
func (c *VIFConfigurator) Delete(ctx context.Context, item dg.Item) error {
	vif, isVif := item.(VIF)
	if !isVif {
		// Should be unreachable.
		return fmt.Errorf("invalid item type %T, expected VIF", item)
	}
	ifName := vif.HostIfName
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to select veth peer %s for removal: %w", ifName, err)
	}
	err = netlink.LinkDel(link)
	if err != nil {
		return fmt.Errorf("failed to delete veth peer %s: %w", ifName, err)
	}
	return nil
}

// NeedsRecreate returns true when anything other than Veth IPs or MTU change.
func (c *VIFConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	oldVif, isVif := oldItem.(VIF)
	if !isVif {
		// Should be unreachable.
		return true
	}
	newVif, isVif := newItem.(VIF)
	if !isVif {
		// Should be unreachable.
		return true
	}
	return oldVif.HostIfName != newVif.HostIfName ||
		oldVif.NetAdapterName != newVif.NetAdapterName ||
		oldVif.Variant.External != newVif.Variant.External ||
		oldVif.Variant.Veth.ForApp != newVif.Variant.Veth.ForApp ||
		oldVif.Variant.Veth.AppIfName != newVif.Variant.Veth.AppIfName ||
		!bytes.Equal(oldVif.Variant.Veth.AppIfMAC, newVif.Variant.Veth.AppIfMAC)
}
