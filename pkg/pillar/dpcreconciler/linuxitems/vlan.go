// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Vlan : VLAN sub-interface.
type Vlan struct {
	// LogicalLabel : logical label used for the VLAN sub-interface.
	LogicalLabel string
	// IfName : name of the VLAN sub-interface in the OS.
	IfName string
	// ParentLL : Logical label of the parent port.
	ParentLL string
	// ParentIfName : name of the parent interface in the OS.
	ParentIfName string
	// VLAN ID.
	ID uint16
	// MTU : Maximum transmission unit size.
	MTU uint16
}

// Name returns the physical name of the VLAN sub-interface.
func (v Vlan) Name() string {
	return v.IfName
}

// Label returns the logical label of the VLAN adapter.
func (v Vlan) Label() string {
	return v.LogicalLabel
}

// Type of the item.
func (v Vlan) Type() string {
	return genericitems.VlanTypename
}

// Equal is a comparison method for two equally-named VLAN instances.
func (v Vlan) Equal(other depgraph.Item) bool {
	v2 := other.(Vlan)
	return v.ParentIfName == v2.ParentIfName &&
		v.ID == v2.ID &&
		v.MTU == v2.MTU
}

// External returns false.
func (v Vlan) External() bool {
	return false
}

// String describes the VLAN sub-interface.
func (v Vlan) String() string {
	return fmt.Sprintf("VLAN Sub-interface: %#+v", v)
}

// Dependencies lists the parent adapter as the only dependency.
func (v Vlan) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterTypename,
				ItemName: v.ParentIfName,
			},
			MustSatisfy: func(item depgraph.Item) bool {
				adapter, isAdapter := item.(Adapter)
				if !isAdapter {
					// unreachable
					return false
				}
				// The adapter must be configured for use as a VLAN parent,
				// and its MTU must be greater than or equal to the VLAN MTU.
				return adapter.UsedAsVlanParent && adapter.GetMTU() >= v.GetMTU()
			},
			Description: "Adapter of the parent interface must exist",
		},
	}
}

// GetMTU returns MTU configured for the Vlan.
func (v Vlan) GetMTU() uint16 {
	if v.MTU == 0 {
		return types.DefaultMTU
	}
	return v.MTU
}

// VlanConfigurator implements Configurator interface (libs/reconciler) for VLAN sub-interfaces.
type VlanConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create creates a VLAN sub-interface.
func (c *VlanConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	vlanCfg := item.(Vlan)
	parentLink, err := netlink.LinkByName(vlanCfg.ParentIfName)
	if err != nil {
		err = fmt.Errorf("failed to get parent interface %s: %v",
			vlanCfg.ParentIfName, err)
		c.Log.Error(err)
		return err
	}
	vlan := &netlink.Vlan{}
	vlan.ParentIndex = parentLink.Attrs().Index
	vlan.Name = vlanCfg.IfName
	vlan.VlanId = int(vlanCfg.ID)
	vlan.MTU = int(vlanCfg.GetMTU())
	err = netlink.LinkAdd(vlan)
	if err != nil {
		err = fmt.Errorf("failed to add VLAN sub-interface %s: %v",
			vlanCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	// Ensure the parent interface is set to UP before bringing up the VLAN subinterface.
	// Otherwise, netlink.LinkSetUp(vlan) will return a "network is down" error.
	err = netlink.LinkSetUp(parentLink)
	if err != nil {
		err = fmt.Errorf("failed to set parent interface %s UP: %v",
			vlanCfg.ParentIfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkSetUp(vlan)
	if err != nil {
		err = fmt.Errorf("failed to set VLAN sub-interface %s UP: %v",
			vlanCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify is only able to change the MTU attribute.
func (c *VlanConfigurator) Modify(_ context.Context, _, newItem depgraph.Item) (err error) {
	vlan, isVlan := newItem.(Vlan)
	if !isVlan {
		return fmt.Errorf("invalid item type %T, expected Vlan", newItem)
	}
	vlanLink, err := netlink.LinkByName(vlan.IfName)
	if err != nil {
		err = fmt.Errorf("failed to get VLAN sub-interface %s link: %v", vlan.IfName, err)
		c.Log.Error(err)
		return err
	}
	if vlanLink.Type() == "bridge" {
		// Most likely renamed to "k" + ifName by the Adapter.
		vlanLink, err = netlink.LinkByName("k" + vlan.IfName)
		if err != nil {
			err = fmt.Errorf("failed to get VLAN sub-interface k%s link: %v",
				vlan.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	mtu := vlan.GetMTU()
	if vlanLink.Attrs().MTU != int(mtu) {
		err = netlink.LinkSetMTU(vlanLink, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for VLAN sub-interface %s: %w",
				mtu, vlan.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Delete removes VLAN sub-interface.
func (c *VlanConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	// After removing interfaces it is best to clear the cache.
	defer c.NetworkMonitor.ClearCache()
	vlanCfg := item.(Vlan)
	link, err := netlink.LinkByName(vlanCfg.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select VLAN sub-interface %s for removal: %v",
			vlanCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkDel(link)
	if err != nil {
		err = fmt.Errorf("failed to delete VLAN sub-interface %s: %v",
			vlanCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate return true if anything other than MTU changes.
// Only MTU can be changed without recreating VLAN sub-interface.
func (c *VlanConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldCfg, isVlan := oldItem.(Vlan)
	if !isVlan {
		// unreachable
		return false
	}
	newCfg, isVlan := newItem.(Vlan)
	if !isVlan {
		// unreachable
		return false
	}
	return oldCfg.ParentIfName != newCfg.ParentIfName ||
		oldCfg.ID != newCfg.ID
}
