// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// PhysIf : network interface corresponding to a physical NIC (Ethernet, WiFi or
// a cellular modem).
// The purpose of this item is two-fold. First, it is used to configure some attributes
// of the network interface, such as MTU. Second, it ensures that the same physical
// interface will not be used by multiple mutually exclusive adapters from higher layers.
// This works by placing PhysIf between NetIO and L2/L3 adapters and by requesting
// re-creation of PhysIf if Usage or MasterIfName changes, thus triggering re-create
// of all higher-layers adapters.
// For example, if eth0 is being used by bond0 and in the next DPC it is instead configured
// as VLAN parent, Usage and MasterIfName will differ between the current and the new DPC
// and will therefore trigger re-create, causing bond0 to be deleted *before* VLAN
// sub-interfaces are created. Without this dependency scheme of PhysIf, the reconciler
// could try to create VLAN sub-interface while eth0 is still aggregated by bond0.
// Dependencies of neither bond nor VLAN would prevent that - they only describe what
// is needed (parent interface, i.e. eth0 in the example) and do not allow to express
// the mutual exclusivity.
type PhysIf struct {
	// PhysIfLL : logical label of the physical interface.
	PhysIfLL string
	// IfName : Interface name of the physical interface.
	PhysIfName string
	// Usage : How is the physical network interface being used.
	Usage genericitems.IOUsage
	// MasterIfName : higher-layer adapter that uses this physical interface as its slave.
	// Currently used only with bonds.
	MasterIfName string
	// WirelessType is used to distinguish between Ethernet, WiFi and cellular port.
	WirelessType types.WirelessType
	// MTU : Maximum transmission unit size.
	MTU uint16
}

// Name returns the physical interface name.
func (p PhysIf) Name() string {
	return p.PhysIfName
}

// Label returns the logical label.
func (p PhysIf) Label() string {
	return p.PhysIfLL + " (interface)"
}

// Type of the item.
func (p PhysIf) Type() string {
	return genericitems.PhysIfTypename
}

// Equal is a comparison method for two equally-named PhysIf instances.
func (p PhysIf) Equal(other depgraph.Item) bool {
	p2, isPhysIf := other.(PhysIf)
	if !isPhysIf {
		return false
	}
	return p.Usage == p2.Usage &&
		p.MasterIfName == p2.MasterIfName &&
		p.WirelessType == p.WirelessType &&
		p.MTU == p2.MTU
}

// External returns false.
func (p PhysIf) External() bool {
	return false
}

// String describes the interface.
func (p PhysIf) String() string {
	return fmt.Sprintf("Physical Network Interface: %#+v", p)
}

// Dependencies returns the network IO device as the only dependency.
func (p PhysIf) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.NetIOTypename,
				ItemName: p.PhysIfName,
			},
			Description: "Underlying network IO device must exist",
		},
	}
}

// GetMTU returns MTU configured for the physical interface.
func (p PhysIf) GetMTU() uint16 {
	if p.MTU == 0 {
		return types.DefaultMTU
	}
	return p.MTU
}

// PhysIfConfigurator implements Configurator interface (libs/reconciler) for PhysIf.
type PhysIfConfigurator struct {
	Log *base.LogObject
}

// Create configures attributes of the physical network interface (currently only MTU).
func (c *PhysIfConfigurator) Create(_ context.Context, item depgraph.Item) error {
	physIf, isPhysIf := item.(PhysIf)
	if !isPhysIf {
		return fmt.Errorf("invalid item type %T, expected PhysIf", item)
	}
	return c.updateMTU(physIf.PhysIfName, physIf.WirelessType, physIf.GetMTU())
}

func (c *PhysIfConfigurator) updateMTU(ifName string, wType types.WirelessType,
	mtu uint16) error {
	if wType == types.WirelessTypeCellular {
		// MTU for cellular port is set by the wwan microservice.
		return nil
	}
	physLink, err := netlink.LinkByName(ifName)
	if err != nil {
		err = fmt.Errorf("failed to get physical interface %s link: %v", ifName, err)
		c.Log.Error(err)
		return err
	}
	if physLink.Type() == "bridge" {
		// Most likely renamed to "k" + ifName by the Adapter.
		physLink, err = netlink.LinkByName("k" + ifName)
		if err != nil {
			err = fmt.Errorf("failed to get physical interface k%s link: %v", ifName, err)
			c.Log.Error(err)
			return err
		}
	}
	if physLink.Attrs().MTU != int(mtu) {
		err = netlink.LinkSetMTU(physLink, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for physical interface %s: %w",
				mtu, ifName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Modify is able to change the MTU value.
func (c *PhysIfConfigurator) Modify(_ context.Context, _, newItem depgraph.Item) (err error) {
	physIf, isPhysIf := newItem.(PhysIf)
	if !isPhysIf {
		return fmt.Errorf("invalid item type %T, expected PhysIf", newItem)
	}
	return c.updateMTU(physIf.PhysIfName, physIf.WirelessType, physIf.GetMTU())
}

// Delete sets the default network interface attributes.
func (c *PhysIfConfigurator) Delete(_ context.Context, item depgraph.Item) error {
	physIf, isPhysIf := item.(PhysIf)
	if !isPhysIf {
		return fmt.Errorf("invalid item type %T, expected PhysIf", item)
	}
	return c.updateMTU(physIf.PhysIfName, physIf.WirelessType, types.DefaultMTU)
}

// NeedsRecreate returns true if Usage or MasterIfName changed. This will intentionally
// trigger recreate which cascades to higher-layer adapters.
func (c *PhysIfConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldCfg, isPhysIf := oldItem.(PhysIf)
	if !isPhysIf {
		// unreachable
		return false
	}
	newCfg, isPhysIf := newItem.(PhysIf)
	if !isPhysIf {
		// unreachable
		return false
	}
	return oldCfg.MasterIfName != newCfg.MasterIfName ||
		oldCfg.Usage != newCfg.Usage
}
