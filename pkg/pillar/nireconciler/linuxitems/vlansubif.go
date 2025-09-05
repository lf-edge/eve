// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"fmt"

	dg "github.com/lf-edge/eve-libs/depgraph"
)

// VLANSubIf : VLAN sub-interface.
// This is external item since VLAN sub-interfaces are created by NIM, not by zedrouter.
type VLANSubIf struct {
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
}

// Name returns the physical name of the VLAN sub-interface.
func (v VLANSubIf) Name() string {
	return v.IfName
}

// Label returns the logical label of the VLAN sub-interface.
func (v VLANSubIf) Label() string {
	return v.LogicalLabel + " (VLAN sub-interface)"
}

// Type of the item.
func (v VLANSubIf) Type() string {
	return VLANSubIntfTypename
}

// Equal is a comparison method for two equally-named VLAN sub-interfaces.
func (v VLANSubIf) Equal(other dg.Item) bool {
	v2 := other.(VLANSubIf)
	return v.ParentIfName == v2.ParentIfName &&
		v.ID == v2.ID
}

// External returns true -- VLAN sub-interfaces are created by NIM, not by zedrouter.
func (v VLANSubIf) External() bool {
	return true
}

// String describes the VLAN sub-interface.
func (v VLANSubIf) String() string {
	return fmt.Sprintf("VLAN Sub-interface: {ifName: %s, logicalLabel: %s, "+
		"parentIfName: %s, parentLogicalLabel: %s, vlan ID: %d}", v.IfName, v.LogicalLabel,
		v.ParentIfName, v.ParentLL, v.ID)
}

// Dependencies returns nothing (external item).
func (v VLANSubIf) Dependencies() (deps []dg.Dependency) {
	return nil
}
