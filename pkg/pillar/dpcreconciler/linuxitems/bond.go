// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Bond : Bond interface.
type Bond struct {
	types.BondConfig
	// LogicalLabel : logical label used for the Bond interface.
	LogicalLabel string
	// IfName : name of the Bond interface in the OS.
	IfName string
	// AggregatedIfNames : interface names of PhysicalIO network adapters aggregated
	// by this bond.
	AggregatedIfNames []string
	// Usage : How is the bond being used.
	// A change in the usage will trigger bond recreate.
	Usage genericitems.IOUsage // IOUsageBondAggrIf is not applicable
}

// Name returns the physical name of the Bond interface.
func (b Bond) Name() string {
	return b.IfName
}

// Label returns the logical label.
func (b Bond) Label() string {
	return b.LogicalLabel + " (bond)"
}

// Type of the item.
func (b Bond) Type() string {
	return genericitems.BondTypename
}

// Equal is a comparison method for two equally-named Bond instances.
func (b Bond) Equal(other depgraph.Item) bool {
	b2 := other.(Bond)
	return reflect.DeepEqual(b.BondConfig, b2.BondConfig) &&
		reflect.DeepEqual(b.AggregatedIfNames, b2.AggregatedIfNames)
}

// External returns false.
func (b Bond) External() bool {
	return false
}

// String describes Bond interface.
func (b Bond) String() string {
	return fmt.Sprintf("Bond interface: %#+v", b)
}

// Dependencies lists all aggregated interfaces as dependencies.
func (b Bond) Dependencies() (deps []depgraph.Dependency) {
	for _, physIfName := range b.AggregatedIfNames {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.IOHandleTypename,
				ItemName: physIfName,
			},
			// Requires exclusive access to the physical interface.
			MustSatisfy: func(item depgraph.Item) bool {
				ioHandle := item.(genericitems.IOHandle)
				return ioHandle.Usage == genericitems.IOUsageBondAggrIf &&
					ioHandle.MasterIfName == b.IfName
			},
			Description: "Aggregated physical interface must exist",
		})
	}
	return deps
}

// BondConfigurator implements Configurator interface (libs/reconciler) for bond interfaces.
type BondConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create is not yet implemented.
func (c *BondConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	// TODO
	return errors.New("not implemented")
}

// Modify is not yet implemented.
func (c *BondConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	// TODO
	return errors.New("not implemented")
}

// Delete is not yet implemented.
func (c *BondConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	// After removing interfaces it is best to clear the cache.
	defer c.NetworkMonitor.ClearCache()

	// TODO
	return errors.New("not implemented")
}

// NeedsRecreate for now returns true - Modify is not implemented (yet).
func (c *BondConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
