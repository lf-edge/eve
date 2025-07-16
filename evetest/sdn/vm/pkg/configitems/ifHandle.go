// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const defaultMTU = 1500

// IfUsage : how a network interface is being used.
type IfUsage uint8

const (
	// IfUsageUnspecified : not specified how a network interface is being used.
	IfUsageUnspecified IfUsage = iota
	// IfUsageL3 : network interface is used in the L3 mode.
	IfUsageL3
	// IfUsageBridged : network interface is bridged.
	IfUsageBridged
	// IfUsageAggregated : network interface is aggregated by Bond interface.
	IfUsageAggregated
)

// IfHandle : an item representing *exclusive* allocation and use of a physical interface.
type IfHandle struct {
	// PhysIf : physical interface associated with this handle.
	PhysIf PhysIf
	// Usage : How is the physical network interface being used.
	Usage IfUsage
	// ParentLL : Logical label of the parent bridge or bond if the physical interface
	// is bridged or aggregated, respectively.
	// Leave empty for L3 interfaces.
	ParentLL string
	// AdminUP : enable to put the physical interface administratively UP.
	AdminUP bool
	// MTU : Maximum transmission unit.
	MTU uint16
}

// Name returns the name of the interface handle item.
func (h IfHandle) Name() string {
	return h.PhysIf.MAC.String()
}

// Label returns the label of the interface handle item.
func (h IfHandle) Label() string {
	return h.PhysIf.LogicalLabel + " (handle)"
}

// Type returns the typename of the interface handle item.
func (h IfHandle) Type() string {
	return IfHandleTypename
}

// Equal is a comparison method for two equally-named IfHandle instances.
func (h IfHandle) Equal(other depgraph.Item) bool {
	h2 := other.(IfHandle)
	return h.Usage == h2.Usage &&
		h.ParentLL == h2.ParentLL &&
		h.AdminUP == h2.AdminUP &&
		h.MTU == h2.MTU
}

// External returns false.
func (h IfHandle) External() bool {
	return false
}

// String describes the handle.
func (h IfHandle) String() string {
	return fmt.Sprintf("Physical Network Interface Handle: %#+v", h)
}

// Dependencies returns the physical interface as the only dependency.
func (h IfHandle) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: PhysIfTypename,
				ItemName: h.PhysIf.MAC.String(),
			},
			Description: "Underlying physical network interface must exist",
		},
	}
}

// IfHandleConfigurator implements Configurator interface for IfHandle.
type IfHandleConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create sets interface admin state and MTU.
func (c *IfHandleConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	ifHandle := item.(IfHandle)
	return c.setIfProperties(ifHandle.PhysIf.MAC, ifHandle.AdminUP, ifHandle.MTU)
}

// Modify is able to change interface admin status and MTU.
func (c *IfHandleConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	ifHandle := newItem.(IfHandle)
	return c.setIfProperties(ifHandle.PhysIf.MAC, ifHandle.AdminUP, ifHandle.MTU)
}

func (c *IfHandleConfigurator) setIfProperties(mac net.HardwareAddr, up bool, mtu uint16) error {
	netIf, found := c.MacLookup.GetInterfaceByMAC(mac, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", mac)
		log.Error(err)
		return err
	}
	link, err := netlink.LinkByName(netIf.IfName)
	if err != nil {
		err = fmt.Errorf("netlink.LinkByName(%s) failed: %v", netIf.IfName, err)
		log.Error(err)
		return err
	}
	if up {
		err = netlink.LinkSetUp(link)
		if err != nil {
			err = fmt.Errorf("netlink.LinkSetUp(%s) failed: %v", link.Attrs().Name, err)
			log.Error(err)
			return err
		}
	} else {
		err = netlink.LinkSetDown(link)
		if err != nil {
			err = fmt.Errorf("netlink.LinkSetDown(%s) failed: %v", link.Attrs().Name, err)
			log.Error(err)
			return err
		}
	}
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

// Delete sets interface DOWN.
func (c *IfHandleConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	ifHandle := item.(IfHandle)
	return c.setIfProperties(ifHandle.PhysIf.MAC, false, 0)
}

// NeedsRecreate returns true if the usage of PhysIf changed.
// This triggers recreate which cascades up through the graph of dependencies.
func (c *IfHandleConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	oldIfHandle := oldItem.(IfHandle)
	newIfHandle := newItem.(IfHandle)
	if oldIfHandle.Usage != newIfHandle.Usage || oldIfHandle.ParentLL != newIfHandle.ParentLL {
		return true
	}
	return false
}
