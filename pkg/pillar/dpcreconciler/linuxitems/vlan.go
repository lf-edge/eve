// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"

	"github.com/lf-edge/eve/libs/depgraph"
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
	// ParentL2Type : link type of the parent interface (bond or physical).
	ParentL2Type types.L2LinkType
	// VLAN ID.
	ID uint16
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
		v.ParentL2Type == v2.ParentL2Type &&
		v.ID == v2.ID
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
	var depType string
	var mustSatisfy func(item depgraph.Item) bool
	switch v.ParentL2Type {
	case types.L2LinkTypeNone:
		// Attached directly to a physical interface.
		// In this case the physical IO has to be "allocated" for use
		// as a VLAN parent interface.
		depType = genericitems.IOHandleTypename
		mustSatisfy = func(item depgraph.Item) bool {
			ioHandle := item.(genericitems.IOHandle)
			return ioHandle.Usage == genericitems.IOUsageVlanParent
		}
	case types.L2LinkTypeVLAN:
		panic("unreachable")
	case types.L2LinkTypeBond:
		depType = genericitems.BondTypename
	}
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: depType,
				ItemName: v.ParentIfName,
			},
			MustSatisfy: mustSatisfy,
			Description: "Parent interface must exist",
		},
	}
}

// VlanConfigurator implements Configurator interface (libs/reconciler) for VLAN sub-interfaces.
type VlanConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create is not yet implemented.
func (c *VlanConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	// TODO
	return errors.New("not implemented")
}

// Modify is not yet implemented.
func (c *VlanConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	// TODO
	return errors.New("not implemented")
}

// Delete is not yet implemented.
func (c *VlanConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	// After removing interfaces it is best to clear the cache.
	defer c.NetworkMonitor.ClearCache()

	// TODO
	return errors.New("not implemented")
}

// NeedsRecreate returns true for now - Modify is not implemented (yet).
func (c *VlanConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
