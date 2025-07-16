// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Veth : virtual Ethernet (two interconnected peers).
type Veth struct {
	// VethName : logical name for the veth pair as a whole.
	VethName string
	Peer1    VethPeer
	Peer2    VethPeer
}

// VethPeer : one side of Virtual Ethernet Device.
type VethPeer struct {
	// IfName : name of the veth peer.
	IfName string
	// MasterBridge : bridge to put veth peer under.
	// Leave nil to use veth peer without bridge.
	// Do not combine with non-main NetNamespace (bridges are limited to main ns)
	// and IPAddresses.
	MasterBridge *MasterBridge
	// NetNamespace : network namespace where the veth peer should be placed into.
	// Do not combine non-main namespace with MasterBridge.
	NetNamespace string
	// IPAddresses : IP addresses to assign to the veth peer.
	// The peer should be in the L3 mode, not under a bridge.
	IPAddresses []*net.IPNet
	// MTU : Maximum transmission unit.
	MTU uint16
}

// MasterBridge : master bridge for a veth peer.
type MasterBridge struct {
	// IfName : interface name of the bridge to put the veth peer under.
	IfName string
	// VLAN for which this VETH is an access port.
	// Leave zero to not use with VLAN.
	VLAN uint16
}

// Name returns the name of the veth pair item.
func (v Veth) Name() string {
	return v.VethName
}

// Label returns the label of the veth pair item.
func (v Veth) Label() string {
	return v.VethName + " (veth)"
}

// Type returns the typename of the veth pair item.
func (v Veth) Type() string {
	return VethTypename
}

// Equal is a comparison method for two equally-named Veth instances.
func (v Veth) Equal(other depgraph.Item) bool {
	v2 := other.(Veth)
	return v.Peer1.Equal(v2.Peer1) &&
		v.Peer2.Equal(v2.Peer2)
}

// Equal compares two veth peers for equality.
func (v VethPeer) Equal(v2 VethPeer) bool {
	if v.IfName != v2.IfName ||
		v.NetNamespace != v2.NetNamespace ||
		v.MTU != v2.MTU {
		return false
	}
	if !generics.EqualSetsFn(v.IPAddresses, v2.IPAddresses, netutils.EqualIPNets) {
		return false
	}
	if v.MasterBridge == nil || v2.MasterBridge == nil {
		return v.MasterBridge == v2.MasterBridge
	}
	return v.MasterBridge.IfName == v2.MasterBridge.IfName &&
		v.MasterBridge.VLAN == v2.MasterBridge.VLAN
}

// External returns false.
func (v Veth) External() bool {
	return false
}

// String describes veth.
func (v Veth) String() string {
	return fmt.Sprintf("veth: %#+v", v)
}

// Dependencies lists namespace and potentially bridge as veth dependencies.
func (v Veth) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, v.Peer1.Dependencies()...)
	deps = append(deps, v.Peer2.Dependencies()...)
	return deps
}

// Dependencies of a single veth side.
func (v VethPeer) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: NetNamespaceTypename,
			ItemName: normNetNsName(v.NetNamespace),
		},
		Description: "Network namespace must exist",
	})
	if v.MasterBridge != nil {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: BridgeTypename,
				ItemName: v.MasterBridge.IfName,
			},
			Description: "Bridge interface must exist",
		})
	}
	// If this peer has IPv6 addresses, require Sysctl with DAD disabled to be
	// applied first so the addresses are immediately bindable (no tentative period).
	for _, ipNet := range v.IPAddresses {
		if ipNet.IP.To4() == nil {
			deps = append(deps, depgraph.Dependency{
				RequiredItem: depgraph.ItemRef{
					ItemType: SysctlTypename,
					ItemName: normNetNsName(v.NetNamespace),
				},
				MustSatisfy: func(item depgraph.Item) bool {
					sysctl, ok := item.(Sysctl)
					return ok && sysctl.DisableIPv6DAD
				},
				Description: "Sysctl with IPv6 DAD disabled must exist before IPv6 addresses are assigned",
			})
			break
		}
	}
	return deps
}

// VethConfigurator implements Configurator interface for veth.
type VethConfigurator struct{}

// Create adds new veth.
func (c *VethConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	vethCfg := item.(Veth)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = vethCfg.Peer1.IfName
	link := &netlink.Veth{
		LinkAttrs: attrs,
		PeerName:  vethCfg.Peer2.IfName,
	}
	if err := netlink.LinkAdd(link); err != nil {
		err = fmt.Errorf("failed to add veth %s/%s: %v",
			vethCfg.Peer1.IfName, vethCfg.Peer2.IfName, err)
		log.Error(err)
		return err
	}
	if err := c.configurePeer(vethCfg.Peer1); err != nil {
		log.Error(err)
		return err
	}
	if err := c.configurePeer(vethCfg.Peer2); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (c *VethConfigurator) configurePeer(peer VethPeer) error {
	// Get the interface link handle.
	link, err := netlink.LinkByName(peer.IfName)
	if err != nil {
		return fmt.Errorf("failed to get link for veth peer %s: %w", peer.IfName, err)
	}
	ns := normNetNsName(peer.NetNamespace)
	if ns != MainNsName {
		// Move interface into the namespace (leave ns with defer).
		err = moveLinkToNamespace(link, ns)
		if err != nil {
			return fmt.Errorf("failed to move veth peer %s to net namespace %s: %w",
				peer.IfName, ns, err)
		}
		// Continue configuring veth peer in the target namespace.
		revertNs, err := switchToNamespace(ns)
		if err != nil {
			return fmt.Errorf("failed to switch to net namespace %s: %w", ns, err)
		}
		defer revertNs()
		// Get link for the peer in this namespace.
		link, err = netlink.LinkByName(peer.IfName)
		if err != nil {
			return fmt.Errorf("failed to get link for veth peer %s in ns %s: %w",
				peer.IfName, ns, err)
		}
	}
	if peer.MasterBridge != nil {
		// Put veth peer under the bridge.
		brIfName := peer.MasterBridge.IfName
		bridge, err := netlink.LinkByName(brIfName)
		if err != nil {
			return fmt.Errorf("failed to get bridge %s "+
				"(for enslavement of veth peer %s): %w", brIfName, peer.IfName, err)
		}
		mtu := bridge.Attrs().MTU
		err = netlink.LinkSetMaster(link, bridge)
		if err != nil {
			return fmt.Errorf("failed to put veth peer %s under bridge %s: %w",
				peer.IfName, brIfName, err)
		}
		// MTU is sometimes lost when new interface is put under the bridge.
		err = netlink.LinkSetMTU(bridge, mtu)
		if err != nil {
			return fmt.Errorf("failed to restore bridge %s MTU %d "+
				"(after enslaving veth peer %s): %w", brIfName, mtu, peer.IfName, err)
		}
		if peer.MasterBridge.VLAN != 0 {
			err = netlink.BridgeVlanAdd(link, peer.MasterBridge.VLAN,
				true, true, false, false)
			if err != nil {
				return fmt.Errorf("failed to add VLAN %d to veth peer %s: %w",
					peer.MasterBridge.VLAN, peer.IfName, err)
			}
			// Do not let untagged traffic to come through this VETH interface.
			err = netlink.BridgeVlanDel(link, 1, false, true, false, false)
			// Ignore error if the rule for native VLAN was not automatically added.
			if err != nil {
				log.Warnf("Failed to remove native VLAN from veth peer %s: %v",
					peer.IfName, err)
				err = nil
			}
		}
	}
	// Set link UP.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set veth peer %s UP: %v", peer.IfName, err)
	}
	// Assign IP addresses.
	for _, ipNet := range peer.IPAddresses {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add addr %v to veth peer %s: %v",
				ipNet, peer.IfName, err)
		}
	}
	// Set MTU.
	mtu := peer.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	err = netlink.LinkSetMTU(link, int(mtu))
	if err != nil {
		err = fmt.Errorf("netlink.LinkSetMTU(%s, %d) failed: %v",
			link.Attrs().Name, mtu, err)
		log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented (veth is recreated on change).
func (c *VethConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes veth.
// Should be enough to just remove one side.
func (c *VethConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	vethCfg := item.(Veth)
	ns := normNetNsName(vethCfg.Peer1.NetNamespace)
	if ns != MainNsName {
		// Move into the namespace with the peer (leave on defer).
		revertNs, err := switchToNamespace(ns)
		if err != nil {
			return fmt.Errorf("failed to switch to net namespace %s: %w", ns, err)
		}
		defer revertNs()
	}
	ifName := vethCfg.Peer1.IfName
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

// NeedsRecreate returns true. Modify is not implemented.
func (c *VethConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
