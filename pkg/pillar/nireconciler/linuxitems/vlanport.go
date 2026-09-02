// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/vishvananda/netlink"
)

const (
	firstValidVID = uint16(2)
	lastValidVID  = uint16(4093)
)

// VLANPort : VLAN configuration for a Linux bridge port.
type VLANPort struct {
	// BridgeIfName : interface name of the bridge.
	BridgeIfName string
	// PortIfName : interface name of the bridge port.
	PortIfName string
	// ForVIF : true if this is VLAN config applied to application VIF
	// (and not to device network port or a VLAN subinterface).
	ForVIF bool
	// VLANConfig : VLAN configuration to apply on the bridged interface.
	VLANConfig VLANConfig
	// ExpectedBridgeID: IfInstanceID BridgeIfName is expected to carry. Zero
	// if the bridge is not NIM-managed.
	ExpectedBridgeID types.IfInstanceID
	// ExpectedPortID: IfInstanceID PortIfName is expected to carry.
	// Zero if the port is not NIM-managed (e.g. VIF).
	ExpectedPortID types.IfInstanceID
}

// VLANConfig : VLAN configuration to apply either on a bridge port or as a VLAN sub-interface.
// Exactly one of the fields should be non-nil.
type VLANConfig struct {
	AccessPort *AccessPort // Untagged traffic for a single VLAN (PVID)
	TrunkPort  *TrunkPort  // Tagged traffic for multiple VLANs

	// VLAN sub-interfaces attached to a bridge with VLAN filtering enabled
	// are represented as "self" entries. A "self" entry assigns VLAN membership
	// to the bridge device itself (not its member ports). This is required for
	// the bridge to locally terminate VLAN traffic — for example, on a VLAN
	// sub-interface used for management or a Local NI. Without the "self" entry,
	// the bridge would forward VLAN traffic between ports but drop frames
	// destined for its own sub-interfaces, since from the VLAN filtering
	// perspective the bridge itself acts as the input/output port.
	VLANSubinterface *VLANSubinterface
}

// TrunkPort : port carries tagged traffic from multiple VLANs.
type TrunkPort struct {
	AllVIDs bool // Allow all valid VIDs: <2,4093>
	VIDs    []uint16
}

// AccessPort : port carries untagged traffic from a single VLAN.
type AccessPort struct {
	VID uint16
}

// VLANSubinterface : VLAN configured as a sub-interface of the bridge itself.
type VLANSubinterface struct {
	IfName string
	VID    uint16
}

// Name reuses BridgePortName to get unique ID also for VLANPort (in the scope
// of other VLANPorts).
func (v VLANPort) Name() string {
	return BridgePortName(v.BridgeIfName, v.PortIfName)
}

// Label for VLANPort.
func (v VLANPort) Label() string {
	return fmt.Sprintf("set VLANs for port %s inside bridge %s",
		v.PortIfName, v.BridgeIfName)
}

// Type of the item.
func (v VLANPort) Type() string {
	return VLANPortTypename
}

// Equal compares two VLANPort instances.
func (v VLANPort) Equal(other dg.Item) bool {
	v2, isVLANPort := other.(VLANPort)
	if !isVLANPort {
		return false
	}

	// Compare VLANConfig union type
	switch {
	case v.VLANConfig.TrunkPort != nil && v2.VLANConfig.TrunkPort != nil:
		if v.VLANConfig.TrunkPort.AllVIDs != v2.VLANConfig.TrunkPort.AllVIDs ||
			!generics.EqualSets(v.VLANConfig.TrunkPort.VIDs, v2.VLANConfig.TrunkPort.VIDs) {
			return false
		}
	case v.VLANConfig.AccessPort != nil && v2.VLANConfig.AccessPort != nil:
		if v.VLANConfig.AccessPort.VID != v2.VLANConfig.AccessPort.VID {
			return false
		}
	case v.VLANConfig.VLANSubinterface != nil && v2.VLANConfig.VLANSubinterface != nil:
		if v.VLANConfig.VLANSubinterface.VID != v2.VLANConfig.VLANSubinterface.VID {
			return false
		}
	default:
		// Mismatched config types (e.g., one is trunk, other is access)
		return false
	}

	// Compare common fields
	return v.BridgeIfName == v2.BridgeIfName &&
		v.PortIfName == v2.PortIfName &&
		v.ForVIF == v2.ForVIF &&
		v.ExpectedBridgeID == v2.ExpectedBridgeID &&
		v.ExpectedPortID == v2.ExpectedPortID
}

// External returns false.
func (v VLANPort) External() bool {
	return false
}

// String describes VLANPort.
func (v VLANPort) String() string {
	var vlanConfig string
	switch {
	case v.VLANConfig.TrunkPort != nil:
		vlanConfig = fmt.Sprintf("trunkPort: {allVIDs: %t, vids: %v}",
			v.VLANConfig.TrunkPort.AllVIDs, v.VLANConfig.TrunkPort.VIDs)
	case v.VLANConfig.AccessPort != nil:
		vlanConfig = fmt.Sprintf("accessPort: {vid: %d}",
			v.VLANConfig.AccessPort.VID)
	case v.VLANConfig.VLANSubinterface != nil:
		vlanConfig = fmt.Sprintf("vlanSubinterface: {vid: %d}",
			v.VLANConfig.VLANSubinterface.VID)
	default:
		vlanConfig = "vlanConfig: none"
	}
	return fmt.Sprintf(
		"VLANPort: {bridgeIfName: %s, portIfName: %s, forVIF: %t, %s, "+
			"expectedBridgeID: %d, expectedPortID: %d}",
		v.BridgeIfName, v.PortIfName, v.ForVIF, vlanConfig,
		v.ExpectedBridgeID, v.ExpectedPortID,
	)
}

// Dependencies returns the (VLAN-enabled) bridge and the port as the dependencies.
func (v VLANPort) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.ItemRef{
			ItemType: VLANBridgeTypename,
			ItemName: v.BridgeIfName,
		},
		Description: "Bridge must exist and have VLANs enabled",
		Attributes: dg.DependencyAttributes{
			AutoDeletedByExternal: true,
		},
	})
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.ItemRef{
			ItemType: BridgePortTypename,
			ItemName: BridgePortName(v.BridgeIfName, v.PortIfName),
		},
		MustSatisfy: func(item dg.Item) bool {
			bridgePort, isBridgePort := item.(BridgePort)
			if !isBridgePort {
				// unreachable
				return false
			}
			if v.VLANConfig.VLANSubinterface != nil {
				// Make sure that VID of VLANPort and BridgePort match.
				bpSubIf := bridgePort.Variant.VLANSubinterface
				if bpSubIf == nil || bpSubIf.VID != v.VLANConfig.VLANSubinterface.VID {
					return false
				}
			}
			// Reject a BridgePort built from a different (older or newer)
			// snapshot of the underlying port/bridge instances -- applying
			// our VLAN config against it could otherwise target a port or
			// bridge that NIM has since renamed or recreated.
			if v.ExpectedPortID != 0 &&
				bridgePort.ExpectedPortID != v.ExpectedPortID {
				return false
			}
			if v.ExpectedBridgeID != 0 &&
				bridgePort.ExpectedBridgeID != v.ExpectedBridgeID {
				return false
			}
			return true
		},
		Description: "Port must be attached to the bridge",
	})
	return deps
}

// VLANPortConfigurator implements Configurator interface (libs/reconciler)
// for VLAN configuration applied to a Linux bridge port.
type VLANPortConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create applies VLAN configuration to a bridge port.
func (c *VLANPortConfigurator) Create(ctx context.Context, item dg.Item) error {
	return c.createOrDelete(item, false)
}

func (c *VLANPortConfigurator) createOrDelete(item dg.Item, del bool) (err error) {
	defer func() {
		if err != nil {
			var linkNotFound netlink.LinkNotFoundError
			if del && errors.As(err, &linkNotFound) {
				// Port was already removed (by hypervisor or domainmgr),
				// but we have not yet received netlink notification about the deletion.
				// Ignore the error.
				err = nil
				return
			}
		}
	}()

	vlanPort, isVLANPort := item.(VLANPort)
	if !isVLANPort {
		return fmt.Errorf("invalid item type %T, expected VLANPort", item)
	}

	portIfName := vlanPort.PortIfName
	bridgeIfName := vlanPort.BridgeIfName
	if del {
		// Resolve by IfInstanceID rather than by name when available: NIM
		// may have since renamed these interfaces away, or even reused
		// their old names for a bridge of its own -- operating on the
		// names as recorded at Create time could silently hit (and
		// modify) unrelated, NIM-owned interfaces.
		if vlanPort.ExpectedPortID != 0 {
			attrs, exists, err := c.NetworkMonitor.GetInterfaceByInstanceID(
				vlanPort.ExpectedPortID)
			if err != nil {
				err = fmt.Errorf("failed to look up interface with IfInstanceID %d: %v",
					vlanPort.ExpectedPortID, err)
				c.Log.Error(err)
				return err
			}
			if !exists {
				// Genuinely gone; nothing left to clean up.
				return nil
			}
			portIfName = attrs.IfName
		}
		if vlanPort.ExpectedBridgeID != 0 {
			attrs, exists, err := c.NetworkMonitor.GetInterfaceByInstanceID(
				vlanPort.ExpectedBridgeID)
			if err != nil {
				err = fmt.Errorf("failed to look up interface with IfInstanceID %d: %v",
					vlanPort.ExpectedBridgeID, err)
				c.Log.Error(err)
				return err
			}
			if !exists {
				return nil
			}
			bridgeIfName = attrs.IfName
		}
	}

	link, err := netlink.LinkByName(portIfName)
	if err != nil {
		err = fmt.Errorf("failed to get link for bridge port %s: %w",
			portIfName, err)
		c.Log.Error(err)
		// Dependencies should prevent this.
		return err
	}

	brLink, err := netlink.LinkByName(bridgeIfName)
	if err != nil {
		err = fmt.Errorf("failed to get link for bridge %s: %w",
			bridgeIfName, err)
		c.Log.Error(err)
		// Dependencies should prevent this.
		return err
	}

	if del && vlanPort.VLANConfig.VLANSubinterface == nil &&
		!stillEnslavedIn(c.NetworkMonitor, link, bridgeIfName, vlanPort.ExpectedBridgeID) {
		// The port has since been repurposed (e.g. re-enslaved by NIM into a
		// bridge of its own): our own VLAN config for it under this bridge
		// is already gone. Touching it now could instead disrupt whatever
		// it is actually attached to.
		return nil
	}

	switch {
	case vlanPort.VLANConfig.TrunkPort != nil:
		const isTrunk = true
		const self = false
		if vlanPort.VLANConfig.TrunkPort.AllVIDs {
			for vid := firstValidVID; vid <= lastValidVID; vid++ {
				if err = c.setVIDForPort(link, vid, isTrunk, self, del); err != nil {
					return err
				}
			}
		} else {
			for _, vid := range vlanPort.VLANConfig.TrunkPort.VIDs {
				if err = c.setVIDForPort(link, vid, isTrunk, self, del); err != nil {
					return err
				}
			}
		}

	case vlanPort.VLANConfig.AccessPort != nil:
		const isTrunk = false
		const self = false
		vid := vlanPort.VLANConfig.AccessPort.VID
		if err = c.setVIDForPort(link, vid, isTrunk, self, del); err != nil {
			return err
		}

	case vlanPort.VLANConfig.VLANSubinterface != nil:
		// Add VLAN ID to the bridge itself ("self" mode), not to the sub-interface.
		// In this mode the port is neither trunk nor access.
		const isTrunk = false
		const self = true
		vid := vlanPort.VLANConfig.VLANSubinterface.VID
		if err = c.setVIDForPort(brLink, vid, isTrunk, self, del); err != nil {
			return err
		}
	}

	return nil
}

func (c *VLANPortConfigurator) setVIDForPort(
	link netlink.Link, vid uint16, trunk, self, del bool) (err error) {
	pvid := !trunk && !self // PVID only applies to access ports
	untagged := !trunk && !self
	const master = false

	if del {
		err = netlink.BridgeVlanDel(link, vid, pvid, untagged, self, master)
	} else {
		err = netlink.BridgeVlanAdd(link, vid, pvid, untagged, self, master)
	}
	if err != nil {
		var portType string
		switch {
		case self:
			portType = "self"
		case trunk:
			portType = "trunk"
		default:
			portType = "access"
		}
		op := "enable"
		if del {
			op = "disable"
		}
		err = fmt.Errorf("failed to %s VLAN ID %d for %s port '%s': %w",
			op, vid, portType, link.Attrs().Name, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *VLANPortConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes VLAN configuration from a bridge port.
func (c *VLANPortConfigurator) Delete(ctx context.Context, item dg.Item) error {
	return c.createOrDelete(item, true)
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *VLANPortConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
