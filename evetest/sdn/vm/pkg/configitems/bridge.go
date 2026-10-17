// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Bridge : Linux bridge.
type Bridge struct {
	// IfName : name of the Bridge in the OS.
	IfName string
	// LogicalLabel : label used within the network model.
	LogicalLabel string
	// PhysIfs : physical interfaces to put under the bridge.
	PhysIfs []BridgedPhysIf
	// BondIfs : *interface names* of bonds to put under the bridge.
	BondIfs []BridgedBondIf
	// VLANs : list of VLANs used with this bridge.
	// If empty then this bridge is used without VLAN filtering.
	VLANs []uint16
	// MTU : Maximum transmission unit size.
	MTU uint16
	// WithSTP: enable to run the Spanning Tree Protocol (STP).
	WithSTP bool
}

// BridgedPhysIf : bridged physical interface.
type BridgedPhysIf struct {
	PhysIf
	// VLAN for which this physical interface is an access port.
	// Leave zero to not use as a VLAN access port.
	AccessVLAN uint16
}

// String describes the bridged physical interface.
func (p BridgedPhysIf) String() string {
	return fmt.Sprintf("Bridged Physical Network Interface: %#+v", p)
}

func equalBridgedPhysIfs(p1, p2 BridgedPhysIf) bool {
	return p1.LogicalLabel == p2.LogicalLabel &&
		bytes.Equal(p1.MAC, p2.MAC) &&
		p1.AccessVLAN == p2.AccessVLAN
}

// BridgedBondIf : bridged bond interface.
type BridgedBondIf struct {
	// Bond interface name.
	IfName string
	// VLAN for which this bond is an access port.
	// Leave zero to not use as a VLAN access port.
	AccessVLAN uint16
}

// String describes the bridged bond interface.
func (p BridgedBondIf) String() string {
	return fmt.Sprintf("Bridged Bond Network Interface: %#+v", p)
}

// Name returns the interface name of the bridge.
func (b Bridge) Name() string {
	return b.IfName
}

// Label assigned to the bridge.
func (b Bridge) Label() string {
	return b.LogicalLabel + " (bridge)"
}

// Type assigned to Bridge.
func (b Bridge) Type() string {
	return BridgeTypename
}

// Equal is a comparison method for two equally-named Bridge instances.
func (b Bridge) Equal(other depgraph.Item) bool {
	b2 := other.(Bridge)
	return b.LogicalLabel == b2.LogicalLabel &&
		generics.EqualSetsFn(b.PhysIfs, b2.PhysIfs, equalBridgedPhysIfs) &&
		generics.EqualSets(b.BondIfs, b2.BondIfs) &&
		generics.EqualSets(b.VLANs, b2.VLANs) &&
		b.MTU == b2.MTU && b.WithSTP == b2.WithSTP
}

// External returns false.
func (b Bridge) External() bool {
	return false
}

// String describes Bridge.
func (b Bridge) String() string {
	return fmt.Sprintf("Bridge: %#+v", b)
}

// Dependencies lists all bridged interfaces as dependencies.
func (b Bridge) Dependencies() (deps []depgraph.Dependency) {
	for _, physIf := range b.PhysIfs {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: IfHandleTypename,
				ItemName: physIf.MAC.String(),
			},
			// Requires exclusive access to the physical interface.
			MustSatisfy: func(item depgraph.Item) bool {
				ioHandle := item.(IfHandle)
				return ioHandle.Usage == IfUsageBridged &&
					ioHandle.ParentLL == b.LogicalLabel
			},
			Description: "Bridged physical interface must exist",
		})
	}
	for _, bond := range b.BondIfs {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: BondTypename,
				ItemName: bond.IfName,
			},
			Description: "Bridged bond interface must exist",
		})
	}
	return deps
}

// BridgeConfigurator implements Configurator interface for bond interfaces.
type BridgeConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create adds new Bridge.
func (c *BridgeConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	bridgeCfg := item.(Bridge)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = bridgeCfg.IfName
	bridge := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(bridge); err != nil {
		err = fmt.Errorf("failed to add bridge %s: %v", bridgeCfg.IfName, err)
		log.Error(err)
		return err
	}
	if err := netlink.LinkSetUp(bridge); err != nil {
		err = fmt.Errorf("failed to set bridge %s UP: %v", bridgeCfg.IfName, err)
		log.Error(err)
		return err
	}
	// Put interface under the bridge using the Modify handler.
	emptyBridge := Bridge{
		IfName:       bridgeCfg.IfName,
		LogicalLabel: bridgeCfg.LogicalLabel,
	}
	return c.handleModify(emptyBridge, bridgeCfg)
}

func (c *BridgeConfigurator) putIfUnderBridge(bridge *netlink.Bridge, ifName string) error {
	mtu := bridge.MTU
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	err = netlink.LinkSetDown(link)
	if err != nil {
		return err
	}
	err = netlink.LinkSetMaster(link, bridge)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}
	// MTU is sometimes lost when new interface is put under the bridge.
	err = netlink.LinkSetMTU(bridge, mtu)
	if err != nil {
		return err
	}
	return nil
}

func (c *BridgeConfigurator) delIfFromBridge(ifName string) error {
	aggrLink, err := netlink.LinkByName(ifName)
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

func (c *BridgeConfigurator) updateVLANs(ifName string, prevVLANs, newVLANs []uint16,
	wasAccess, isAccess bool) error {

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get link %s for VLAN update: %w", ifName, err)
	}

	// Determine VLANs to remove/add
	var toRemove, toAdd []uint16
	if wasAccess == isAccess {
		toRemove, toAdd = generics.DiffSets(prevVLANs, newVLANs)
	} else {
		// Port mode changed → reprogram everything
		toRemove = prevVLANs
		toAdd = newVLANs
	}

	flags := func(access bool) (pvid, untagged bool, portType string) {
		if access {
			return true, true, "access"
		}
		return false, false, "trunk"
	}

	// Remove VLANs
	for _, vlanID := range toRemove {
		pvid, untagged, portType := flags(wasAccess)
		err = netlink.BridgeVlanDel(link, vlanID, pvid, untagged, false, false)
		if err != nil {
			return fmt.Errorf(
				"failed to remove VLAN (%d) from (%s) port '%s': %w",
				vlanID, portType, ifName, err,
			)
		}
	}

	// Add VLANs
	for _, vlanID := range toAdd {
		pvid, untagged, portType := flags(isAccess)
		err = netlink.BridgeVlanAdd(link, vlanID, pvid, untagged, false, false)
		if err != nil {
			return fmt.Errorf(
				"failed to add VLAN (%d) to (%s) port '%s': %w",
				vlanID, portType, ifName, err,
			)
		}
	}
	return nil
}

// Modify is able to change the set of bridged interfaces.
func (c *BridgeConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	oldBridgeCfg := oldItem.(Bridge)
	newBridgeCfg := newItem.(Bridge)
	return c.handleModify(oldBridgeCfg, newBridgeCfg)
}

func (c *BridgeConfigurator) handleModify(oldBridgeCfg, newBridgeCfg Bridge) error {
	ifName := oldBridgeCfg.IfName

	bridgeLink, err := netlink.LinkByName(ifName)
	if err != nil {
		log.Error(err)
		return err
	}
	if bridgeLink.Type() != "bridge" {
		err := fmt.Errorf("interface %s is not Bridge", ifName)
		log.Error(err)
		return err
	}
	bridge := bridgeLink.(*netlink.Bridge)

	// Helper: derive VLAN config for a port.
	portVLANConfig := func(bridgeVLANs []uint16, accessVLAN uint16) ([]uint16, bool) {
		if accessVLAN != 0 {
			return []uint16{accessVLAN}, true
		}
		return bridgeVLANs, false
	}

	// Update VLAN filtering.
	vlanFiltering := len(newBridgeCfg.VLANs) > 0
	if *bridge.VlanFiltering != vlanFiltering {
		val := "0"
		if vlanFiltering {
			val = "1"
		}
		// netlink.BridgeSetVlanFiltering seems to be broken, it keeps returning EBUSY.
		// Let's use ip command instead.
		args := []string{
			"link", "set", "dev", ifName, "type", "bridge", "vlan_filtering", val,
		}
		output, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			err = fmt.Errorf(
				"failed to set VLAN filtering to %t for bridge %s: %s",
				vlanFiltering, ifName, output,
			)
			log.Error(err)
			return err
		}
	}

	// Remove physical interfaces no longer under the bridge.
	for _, oldPhysIf := range oldBridgeCfg.PhysIfs {
		var keep bool
		for _, newPhysIf := range newBridgeCfg.PhysIfs {
			if bytes.Equal(oldPhysIf.MAC, newPhysIf.MAC) {
				keep = true
				break
			}
		}
		if !keep {
			netIf, found := c.MacLookup.GetInterfaceByMAC(oldPhysIf.MAC, false)
			if !found {
				return fmt.Errorf("failed to get physical interface with MAC %v",
					oldPhysIf.MAC)
			}
			if err = c.delIfFromBridge(netIf.IfName); err != nil {
				return fmt.Errorf(
					"failed to release interface %s from bridge %s: %w",
					netIf.IfName, ifName, err,
				)
			}
		}
	}

	// Remove bonds no longer under the bridge.
	for _, oldBondIf := range oldBridgeCfg.BondIfs {
		var keep bool
		for _, newBondIf := range newBridgeCfg.BondIfs {
			if oldBondIf.IfName == newBondIf.IfName {
				keep = true
				break
			}
		}
		if !keep {
			if err := c.delIfFromBridge(oldBondIf.IfName); err != nil {
				return fmt.Errorf(
					"failed to release bond %s from bridge %s: %w",
					oldBondIf.IfName, ifName, err,
				)
			}
		}
	}

	// Add / update physical interfaces.
	for _, newPhysIf := range newBridgeCfg.PhysIfs {
		netIf, found := c.MacLookup.GetInterfaceByMAC(newPhysIf.MAC, false)
		if !found {
			return fmt.Errorf("failed to get physical interface with MAC %v",
				newPhysIf.MAC)
		}

		var oldPhysIf *BridgedPhysIf
		for i := range oldBridgeCfg.PhysIfs {
			if bytes.Equal(oldBridgeCfg.PhysIfs[i].MAC, newPhysIf.MAC) {
				oldPhysIf = &oldBridgeCfg.PhysIfs[i]
				break
			}
		}

		if oldPhysIf == nil {
			if err = c.putIfUnderBridge(bridge, netIf.IfName); err != nil {
				return fmt.Errorf(
					"failed to put interface %s under bridge %s: %w",
					netIf.IfName, ifName, err,
				)
			}
		}

		var prevVLANs []uint16
		var wasAccess bool
		if oldPhysIf != nil {
			prevVLANs, wasAccess = portVLANConfig(
				oldBridgeCfg.VLANs, oldPhysIf.AccessVLAN)
		}
		newVLANs, isAccess := portVLANConfig(
			newBridgeCfg.VLANs, newPhysIf.AccessVLAN)

		err = c.updateVLANs(netIf.IfName, prevVLANs, newVLANs, wasAccess, isAccess)
		if err != nil {
			return err
		}
	}

	// Add / update bond interfaces.
	for _, newBondIf := range newBridgeCfg.BondIfs {
		var oldBondIf *BridgedBondIf
		for i := range oldBridgeCfg.BondIfs {
			if oldBridgeCfg.BondIfs[i].IfName == newBondIf.IfName {
				oldBondIf = &oldBridgeCfg.BondIfs[i]
				break
			}
		}

		if oldBondIf == nil {
			if err := c.putIfUnderBridge(bridge, newBondIf.IfName); err != nil {
				return fmt.Errorf(
					"failed to put bond %s under bridge %s: %w",
					newBondIf.IfName, ifName, err,
				)
			}
		}

		var prevVLANs []uint16
		var wasAccess bool
		if oldBondIf != nil {
			prevVLANs, wasAccess = portVLANConfig(oldBridgeCfg.VLANs, oldBondIf.AccessVLAN)
		}
		newVLANs, isAccess := portVLANConfig(
			newBridgeCfg.VLANs, newBondIf.AccessVLAN)

		err = c.updateVLANs(newBondIf.IfName, prevVLANs, newVLANs, wasAccess, isAccess)
		if err != nil {
			return err
		}
	}

	// Update MTU.
	newMTU := newBridgeCfg.MTU
	if newMTU == 0 {
		newMTU = defaultMTU
	}
	if bridge.MTU != int(newMTU) {
		if err := netlink.LinkSetMTU(bridgeLink, int(newMTU)); err != nil {
			return fmt.Errorf(
				"failed to set MTU %d for bridge %s: %w",
				newMTU, ifName, err,
			)
		}
	}

	// Update STP.
	return c.startOrStopSTP(ifName, newBridgeCfg.WithSTP)
}

func (c *BridgeConfigurator) startOrStopSTP(brIfName string, start bool) error {
	if start {
		// Set a low bridge priority so the SDN bridge always wins the STP
		// root election against the connected EVE device (which uses the
		// Linux default of 32768). Priority must be a multiple of 4096;
		// 4096 is guaranteed to be lower than any default-priority bridge.
		prioPath := fmt.Sprintf("/sys/class/net/%s/bridge/priority", brIfName)
		if err := os.WriteFile(prioPath, []byte("4096"), 0644); err != nil {
			return fmt.Errorf("failed to set STP priority for bridge %s: %w",
				brIfName, err)
		}
	}
	sysOptVal := "0"
	action := "stop"
	if start {
		sysOptVal = "1"
		action = "start"
	}
	sysOptPath := fmt.Sprintf("/sys/class/net/%s/bridge/stp_state", brIfName)
	if err := os.WriteFile(sysOptPath, []byte(sysOptVal), 0644); err != nil {
		return fmt.Errorf("failed to %s STP for bridge %s: %w", action, brIfName, err)
	}
	return nil
}

// Delete removes bridge.
func (c *BridgeConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	bridgeCfg := item.(Bridge)
	// Remove all interfaces from under the bridge using the Modify handler.
	emptyBridge := Bridge{
		IfName:       bridgeCfg.IfName,
		LogicalLabel: bridgeCfg.LogicalLabel,
	}
	if err := c.handleModify(bridgeCfg, emptyBridge); err != nil {
		return err
	}
	bridge, err := netlink.LinkByName(bridgeCfg.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select bridge %s for removal: %v",
			bridgeCfg.IfName, err)
		log.Error(err)
		return err
	}
	err = netlink.LinkDel(bridge)
	if err != nil {
		err = fmt.Errorf("failed to delete bridge %s: %v", bridgeCfg.IfName, err)
		log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns false.
// The set of bridged interfaces can be changed without recreating bridge.
func (c *BridgeConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}
