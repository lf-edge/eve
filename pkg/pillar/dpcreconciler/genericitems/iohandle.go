// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// IOUsage : how is network IO being used.
type IOUsage uint8

const (
	// IOUsageUnspecified : not specified how the network IO is being used.
	IOUsageUnspecified IOUsage = iota
	// IOUsageL3Adapter : network IO is used as L3 adapter.
	IOUsageL3Adapter
	// IOUsageVlanParent : network IO is used as VLAN parent interface.
	IOUsageVlanParent
	// IOUsageBondAggrIf : network IO is aggregated by Bond interface.
	IOUsageBondAggrIf
)

// IOHandle : an item representing allocation and use of a physical interface.
// The purpose of this item is to ensure that the same physical interface will not be
// used by multiple mutually exclusive adapters from higher layers.
// This works by placing IOHandle between PhysIf and L2/L3 adapters and by requesting
// re-creation of IOHandle if Usage or MasterIfName changes, thus triggering re-create
// of all higher-layers adapters.
// For example, if eth0 is being used by bond0 and in the next DPC it is instead configured
// as VLAN parent, Usage and MasterIfName will differ between the current and the new DPC
// and will therefore trigger re-create, causing bond0 to be deleted *before* VLAN
// sub-interfaces are created. Without IOHandle, the reconciler could try to create VLAN
// sub-interface while eth0 is still aggregated by bond0. Dependencies of neither bond nor
// VLAN would prevent that - they only describe what is needed (eth0) and do not allow to
// express mutual exclusivity.
type IOHandle struct {
	// PhysIfLL : logical label of the physical interface associated with this handle.
	PhysIfLL string
	// IfName : Interface name of the physical interface associated with this handle.
	PhysIfName string
	// Usage : How is the physical network interface being used.
	Usage IOUsage
	// MasterIfName : higher-layer interface that uses this handle to enslave the physical
	// interface. Currently used only with bonds.
	MasterIfName string
}

// Name returns the physical interface name.
func (h IOHandle) Name() string {
	return h.PhysIfName
}

// Label returns the logical label.
func (h IOHandle) Label() string {
	return h.PhysIfLL + " (handle)"
}

// Type of the item.
func (h IOHandle) Type() string {
	return IOHandleTypename
}

// Equal is a comparison method for two equally-named IOHandle instances.
func (h IOHandle) Equal(other depgraph.Item) bool {
	h2 := other.(IOHandle)
	return h.Usage == h2.Usage &&
		h.MasterIfName == h2.MasterIfName
}

// External returns false.
func (h IOHandle) External() bool {
	return false
}

// String describes the interface.
func (h IOHandle) String() string {
	return fmt.Sprintf("Physical Network Interface Handle: %#+v", h)
}

// Dependencies returns the physical interface as the only dependency.
func (h IOHandle) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: PhysIfTypename,
				ItemName: h.PhysIfName,
			},
			Description: "Underlying physical network interface must exist",
		},
	}
}

// IOHandleConfigurator implements Configurator interface (libs/reconciler) for IOHandle.
type IOHandleConfigurator struct {
	Log *base.LogObject
}

// Create is NOOP - IOHandle is not an actual config item, it is used only for
// dependency purposes (to implement mutual exclusivity for physIf use).
func (c *IOHandleConfigurator) Create(context.Context, depgraph.Item) error {
	return nil
}

// Modify should not be reachable.
func (c *IOHandleConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete is NOOP.
func (c *IOHandleConfigurator) Delete(context.Context, depgraph.Item) error {
	return nil
}

// NeedsRecreate returns true - change in PhysIf usage intentionally triggers recreate
// which cascades to higher-layer adapters.
func (c *IOHandleConfigurator) NeedsRecreate(_, _ depgraph.Item) (recreate bool) {
	return true
}
