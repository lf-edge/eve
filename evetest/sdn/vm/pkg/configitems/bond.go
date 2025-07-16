// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"bytes"
	"context"
	"fmt"
	"github.com/lf-edge/eve-libs/depgraph"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"google.golang.org/protobuf/proto"
	"net"
)

// Bond : Bond interface.
type Bond struct {
	*api.Bond
	// IfName : name of the Bond interface in the OS.
	IfName string
	// AggregatedPhysIfs : list of physical interfaces aggregated by this bond.
	AggregatedPhysIfs []PhysIf
	// MTU : Maximum transmission unit size.
	MTU uint16
}

// Name returns the name of the bond interface.
func (b Bond) Name() string {
	return b.IfName
}

// Label returns the label of the bond interface.
func (b Bond) Label() string {
	return b.GetLogicalLabel() + " (bond)"
}

// Type returns the typename of the bond interface.
func (b Bond) Type() string {
	return BondTypename
}

// Equal is a comparison method for two equally-named Bond instances.
func (b Bond) Equal(other depgraph.Item) bool {
	b2 := other.(Bond)
	return proto.Equal(b.Bond, b2.Bond) &&
		generics.EqualSetsFn(b.AggregatedPhysIfs, b2.AggregatedPhysIfs, equalPhysIfs) &&
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
	for _, physIf := range b.AggregatedPhysIfs {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: IfHandleTypename,
				ItemName: physIf.MAC.String(),
			},
			// Requires exclusive access to the physical interface.
			MustSatisfy: func(item depgraph.Item) bool {
				ioHandle := item.(IfHandle)
				return ioHandle.Usage == IfUsageAggregated &&
					ioHandle.ParentLL == b.GetLogicalLabel()
			},
			Description: "Aggregated physical interface must exist",
		})
	}
	return deps
}

// BondConfigurator implements Configurator interface for bond interfaces.
type BondConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create adds new Bond interface.
func (c *BondConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	bondCfg := item.(Bond)
	bond := netlink.NewLinkBond(netlink.LinkAttrs{Name: bondCfg.IfName})
	switch bondCfg.GetMode() {
	case api.BondMode_BOND_MODE_BALANCE_RR:
		bond.Mode = netlink.BOND_MODE_BALANCE_RR
	case api.BondMode_BOND_MODE_ACTIVE_BACKUP:
		bond.Mode = netlink.BOND_MODE_ACTIVE_BACKUP
	case api.BondMode_BOND_MODE_BALANCE_XOR:
		bond.Mode = netlink.BOND_MODE_BALANCE_XOR
	case api.BondMode_BOND_MODE_BROADCAST:
		bond.Mode = netlink.BOND_MODE_BROADCAST
	case api.BondMode_BOND_MODE_802_3AD:
		bond.Mode = netlink.BOND_MODE_802_3AD
		switch bondCfg.GetLacpRate() {
		case api.LacpRate_LACP_RATE_SLOW:
			bond.LacpRate = netlink.BOND_LACP_RATE_SLOW
		case api.LacpRate_LACP_RATE_FAST:
			bond.LacpRate = netlink.BOND_LACP_RATE_FAST
		}
	case api.BondMode_BOND_MODE_BALANCE_TLB:
		bond.Mode = netlink.BOND_MODE_BALANCE_TLB
	case api.BondMode_BOND_MODE_BALANCE_ALB:
		bond.Mode = netlink.BOND_MODE_BALANCE_ALB
	default:
		err := fmt.Errorf("unsupported Bond mode: %v", bondCfg.GetMode())
		log.Error(err)
		return err
	}
	if bondCfg.GetMiiMonitor().GetEnabled() {
		bond.Miimon = int(bondCfg.GetMiiMonitor().GetInterval())
		bond.UpDelay = int(bondCfg.GetMiiMonitor().GetUpDelay())
		bond.DownDelay = int(bondCfg.GetMiiMonitor().GetDownDelay())
	} else if bondCfg.GetArpMonitor().GetEnabled() {
		bond.ArpInterval = int(bondCfg.GetArpMonitor().GetInterval())
		for _, ipTarget := range bondCfg.GetArpMonitor().GetIpTargets() {
			ip := net.ParseIP(ipTarget)
			if ip == nil {
				log.Warnf("Failed to parse ARP monitor IP target '%s'", ipTarget)
				continue
			}
			if ip.To4() == nil {
				log.Warnf("ARP monitor IP target '%s' is not IPv4 address", ipTarget)
				continue
			}
			bond.ArpIpTargets = append(bond.ArpIpTargets, ip.To4())
		}
	}
	if bondCfg.MTU == 0 {
		bond.MTU = defaultMTU
	} else {
		bond.MTU = int(bondCfg.MTU)
	}
	err := netlink.LinkAdd(bond)
	if err != nil {
		err = fmt.Errorf("failed to add bond: %v", err)
		log.Error(err)
		return err
	}
	err = netlink.LinkSetUp(bond)
	if err != nil {
		err = fmt.Errorf("failed to set bond %s UP: %v", bondCfg.IfName, err)
		log.Error(err)
		return err
	}
	for _, aggrIf := range bondCfg.AggregatedPhysIfs {
		err := c.aggregateInterface(bond, aggrIf.MAC)
		if err != nil {
			err = fmt.Errorf("failed to put interface %s under bond %s: %v",
				aggrIf.LogicalLabel, bondCfg.IfName, err)
			log.Error(err)
			return err
		}
	}
	return nil
}

func (c *BondConfigurator) aggregateInterface(bond *netlink.Bond,
	aggrIfMAC net.HardwareAddr) error {
	netIf, found := c.MacLookup.GetInterfaceByMAC(aggrIfMAC, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", aggrIfMAC)
		log.Error(err)
		return err
	}
	aggrLink, err := netlink.LinkByName(netIf.IfName)
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

func (c *BondConfigurator) disaggregateInterface(aggrIfMAC net.HardwareAddr) error {
	netIf, found := c.MacLookup.GetInterfaceByMAC(aggrIfMAC, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", aggrIfMAC)
		log.Error(err)
		return err
	}
	aggrLink, err := netlink.LinkByName(netIf.IfName)
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
		log.Error(err)
		return err
	}
	if bondLink.Type() != "bond" {
		err = fmt.Errorf("interface %s is not Bond", oldBondCfg.IfName)
		log.Error(err)
		return err
	}
	bond := bondLink.(*netlink.Bond)
	// Disaggregate interfaces which are no longer configured to be under the Bond.
	for _, oldAggrIf := range oldBondCfg.AggregatedPhysIfs {
		var found bool
		for _, newAggrIf := range newBondCfg.AggregatedPhysIfs {
			if bytes.Equal(oldAggrIf.MAC, newAggrIf.MAC) {
				found = true
				break
			}
		}
		if !found {
			err := c.disaggregateInterface(oldAggrIf.MAC)
			if err != nil {
				err = fmt.Errorf("failed to release interface %s from bond %s: %v",
					oldAggrIf.LogicalLabel, oldBondCfg.IfName, err)
				log.Error(err)
				return err
			}
		}
	}
	// Add interfaces newly configured for aggregation under this Bond.
	for _, newAggrIf := range newBondCfg.AggregatedPhysIfs {
		var found bool
		for _, oldAggrIf := range oldBondCfg.AggregatedPhysIfs {
			if bytes.Equal(oldAggrIf.MAC, newAggrIf.MAC) {
				found = true
				break
			}
		}
		if !found {
			err := c.aggregateInterface(bond, newAggrIf.MAC)
			if err != nil {
				err = fmt.Errorf("failed to put interface %s under bond %s: %v",
					newAggrIf.LogicalLabel, oldBondCfg.IfName, err)
				log.Error(err)
				return err
			}
		}
	}
	// Update MTU settings.
	newMTU := newBondCfg.MTU
	if newMTU == 0 {
		newMTU = defaultMTU
	}
	if bond.MTU != int(newMTU) {
		err = netlink.LinkSetMTU(bondLink, int(newMTU))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for bond %s: %w",
				newMTU, oldBondCfg.IfName, err)
			log.Error(err)
			return err
		}
	}
	return nil
}

// Delete removes bond interface.
func (c *BondConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	bondCfg := item.(Bond)
	for _, aggrIf := range bondCfg.AggregatedPhysIfs {
		err := c.disaggregateInterface(aggrIf.MAC)
		if err != nil {
			err = fmt.Errorf("failed to release interface %s from bond %s: %v",
				aggrIf.LogicalLabel, bondCfg.IfName, err)
			return err
		}
	}
	link, err := netlink.LinkByName(bondCfg.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select bond %s for removal: %v",
			bondCfg.IfName, err)
		log.Error(err)
		return err
	}
	err = netlink.LinkDel(link)
	if err != nil {
		err = fmt.Errorf("failed to delete bond %s: %v", bondCfg.IfName, err)
		log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true if Bond attributes have changed.
// The set of aggregated interfaces and MTU can be changed without recreating Bond.
func (c *BondConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldBondCfg := oldItem.(Bond)
	newBondCfg := newItem.(Bond)
	if !proto.Equal(oldBondCfg.Bond, newBondCfg.Bond) {
		return true
	}
	return false
}
