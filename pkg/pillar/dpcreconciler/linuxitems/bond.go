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
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
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
	// MTU : Maximum transmission unit size.
	MTU uint16
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
	return b.LacpRate == b2.LacpRate &&
		b.MIIMonitor == b2.MIIMonitor &&
		b.Mode == b2.Mode &&
		b.ARPMonitor.Equal(b2.ARPMonitor) &&
		generics.EqualSets(b.AggregatedIfNames, b2.AggregatedIfNames) &&
		b.Usage == b2.Usage &&
		b.MTU == b2.MTU
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
				ItemType: genericitems.PhysIfTypename,
				ItemName: physIfName,
			},
			// Requires exclusive access to the physical interface.
			MustSatisfy: func(item depgraph.Item) bool {
				physIf := item.(PhysIf)
				return physIf.Usage == genericitems.IOUsageBondAggrIf &&
					physIf.MasterIfName == b.IfName
			},
			Description: "Aggregated physical interface must exist",
		})
	}
	return deps
}

// GetMTU returns MTU configured for the Bond.
func (b Bond) GetMTU() uint16 {
	if b.MTU == 0 {
		return types.DefaultMTU
	}
	return b.MTU
}

// BondConfigurator implements Configurator interface (libs/reconciler) for bond interfaces.
type BondConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create adds new Bond interface.
func (c *BondConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	bondCfg := item.(Bond)
	bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: bondCfg.IfName})
	switch bondCfg.Mode {
	case types.BondModeUnspecified:
		err := fmt.Errorf("unspecified Bond mode: %v", bondCfg.Mode)
		c.Log.Error(err)
		return err
	case types.BondModeBalanceRR:
		bond.Mode = netlink.BOND_MODE_BALANCE_RR
	case types.BondModeActiveBackup:
		bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
	case types.BondModeBalanceXOR:
		bond.Mode = netlink.BOND_MODE_BALANCE_XOR
	case types.BondModeBroadcast:
		bond.Mode = netlink.BOND_MODE_BROADCAST
	case types.BondMode802Dot3AD:
		bond.Mode = netlink.BOND_MODE_802_3AD
		switch bondCfg.LacpRate {
		case types.LacpRateSlow:
			bond.LacpRate = netlink.BOND_LACP_RATE_SLOW
		case types.LacpRateFast:
			bond.LacpRate = netlink.BOND_LACP_RATE_FAST
		}
	case types.BondModeBalanceTLB:
		bond.Mode = netlink.BOND_MODE_BALANCE_TLB
	case types.BondModeBalanceALB:
		bond.Mode = netlink.BOND_MODE_BALANCE_ALB
	default:
		err := fmt.Errorf("unsupported Bond mode: %v", bondCfg.Mode)
		c.Log.Error(err)
		return err
	}
	bond.Miimon = 0
	bond.ArpInterval = 0
	if bondCfg.MIIMonitor.Enabled {
		bond.DownDelay = int(bondCfg.MIIMonitor.DownDelay)
		bond.UpDelay = int(bondCfg.MIIMonitor.UpDelay)
		bond.Miimon = int(bondCfg.MIIMonitor.Interval)
	} else if bondCfg.ARPMonitor.Enabled {
		bond.ArpInterval = int(bondCfg.ARPMonitor.Interval)
		bond.ArpIpTargets = bondCfg.ARPMonitor.IPTargets
	}
	bond.MTU = int(bondCfg.GetMTU())
	err := netlink.LinkAdd(bond)
	if err != nil {
		err = fmt.Errorf("failed to add bond: %v", err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkSetUp(bond)
	if err != nil {
		err = fmt.Errorf("failed to set bond %s UP: %v", bondCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	for _, aggrIfName := range bondCfg.AggregatedIfNames {
		err := c.aggregateInterface(bond, aggrIfName)
		if err != nil {
			err = fmt.Errorf("failed to put interface %s under bond %s: %v",
				aggrIfName, bondCfg.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

func (c *BondConfigurator) aggregateInterface(bond *netlink.Bond, ifName string) error {
	aggrLink, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	// Interface must be down before it can be put under a bond.
	err = netlink.LinkSetDown(aggrLink)
	if err != nil {
		return err
	}
	err = netlink.LinkSetBondSlave(aggrLink, bond)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(aggrLink)
	if err != nil {
		return err
	}
	return nil
}

func (c *BondConfigurator) disaggregateInterface(aggrIfName string) error {
	aggrLink, err := netlink.LinkByName(aggrIfName)
	if err != nil {
		return err
	}
	err = netlink.LinkSetNoMaster(aggrLink)
	if err != nil {
		return err
	}
	// Releasing interface from the master causes it be automatically
	// brought down - we need to bring it back up.
	err = netlink.LinkSetUp(aggrLink)
	if err != nil {
		return err
	}
	return nil
}

// Modify is able to change the set of aggregated interfaces and MTU.
func (c *BondConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	oldBondCfg := oldItem.(Bond)
	newBondCfg := newItem.(Bond)
	bondLink, err := netlink.LinkByName(oldBondCfg.IfName)
	if err != nil {
		c.Log.Error(err)
		return err
	}
	if bondLink.Type() == "bridge" {
		// Most likely renamed to "k" + ifName by the Adapter.
		bondLink, err = netlink.LinkByName("k" + oldBondCfg.IfName)
		if err != nil {
			err = fmt.Errorf("failed to get bond interface k%s link: %v",
				oldBondCfg.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	if bondLink.Type() != "bond" {
		err = fmt.Errorf("interface %s is not Bond", oldBondCfg.IfName)
		c.Log.Error(err)
		return err
	}
	bond := bondLink.(*netlink.Bond)
	// Disaggregate interfaces which are no longer configured to be under the Bond.
	for _, oldAggrIntf := range oldBondCfg.AggregatedIfNames {
		var found bool
		for _, newAggrIntf := range newBondCfg.AggregatedIfNames {
			if oldAggrIntf == newAggrIntf {
				found = true
				break
			}
		}
		if !found {
			err := c.disaggregateInterface(oldAggrIntf)
			if err != nil {
				err = fmt.Errorf("failed to release interface %s from bond %s: %v",
					oldAggrIntf, oldBondCfg.IfName, err)
				c.Log.Error(err)
				return err
			}
		}
	}
	// Add interfaces newly configured for aggregation under this Bond.
	for _, newAggrIntf := range newBondCfg.AggregatedIfNames {
		var found bool
		for _, oldAggrIntf := range oldBondCfg.AggregatedIfNames {
			if oldAggrIntf == newAggrIntf {
				found = true
				break
			}
		}
		if !found {
			err := c.aggregateInterface(bond, newAggrIntf)
			if err != nil {
				err = fmt.Errorf("failed to put interface %s under bond %s: %v",
					newAggrIntf, oldBondCfg.IfName, err)
				c.Log.Error(err)
				return err
			}
		}
	}
	// Update MTU.
	mtu := newBondCfg.GetMTU()
	if bond.MTU != int(mtu) {
		err = netlink.LinkSetMTU(bondLink, int(mtu))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for bond %s: %w",
				mtu, oldBondCfg.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Delete removes bond interface.
func (c *BondConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	// After removing interfaces it is best to clear the cache.
	defer c.NetworkMonitor.ClearCache()
	bondCfg := item.(Bond)
	for _, aggrIfName := range bondCfg.AggregatedIfNames {
		err := c.disaggregateInterface(aggrIfName)
		if err != nil {
			err = fmt.Errorf("failed to release interface %s from bond %s: %v",
				aggrIfName, bondCfg.IfName, err)
			return err
		}
	}
	link, err := netlink.LinkByName(bondCfg.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select bond %s for removal: %v",
			bondCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkDel(link)
	if err != nil {
		err = fmt.Errorf("failed to delete bond %s: %v", bondCfg.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true if Bond attributes or Usage have changed.
// The set of aggregated interfaces and interface MTU can be changed without recreating Bond.
func (c *BondConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldBondCfg := oldItem.(Bond)
	newBondCfg := newItem.(Bond)
	if oldBondCfg.LacpRate != newBondCfg.LacpRate ||
		oldBondCfg.MIIMonitor != newBondCfg.MIIMonitor ||
		oldBondCfg.Mode != newBondCfg.Mode ||
		!oldBondCfg.ARPMonitor.Equal(newBondCfg.ARPMonitor) {
		return true
	}
	if oldBondCfg.Usage != newBondCfg.Usage {
		return true
	}
	return false
}
