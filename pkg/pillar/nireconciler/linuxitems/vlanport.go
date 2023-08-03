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
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
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
	// BridgePort references the bridged interface to configure VLANs for.
	BridgePort BridgePort
	// VLANConfig : VLAN configuration to apply on the bridged interface.
	VLANConfig VLANConfig
}

// BridgePort : port attached to a bridge.
// Only one of these should be defined (this is like union).
type BridgePort struct {
	// UplinkIfName : bridged uplink interface.
	UplinkIfName string
	// VIFIfName : bridged VIF.
	VIFIfName string
}

// VLANConfig : VLAN configuration to apply on the bridge port.
// Port is either configured as a trunk or as an access port (use this struct as union).
type VLANConfig struct {
	AccessPort *AccessPort
	TrunkPort  *TrunkPort
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

// Name returns the interface name of the bridged port
// (there can be at most one instance of VLANPort associated with a given bridged port).
func (v VLANPort) Name() string {
	return v.portIfName()
}

// Label for VLANPort.
func (v VLANPort) Label() string {
	return v.portIfName() + " (VLAN port)"
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
	isTrunk1 := v.VLANConfig.TrunkPort != nil
	isTrunk2 := v2.VLANConfig.TrunkPort != nil
	if isTrunk1 != isTrunk2 {
		return false
	}
	if isTrunk1 {
		if v.VLANConfig.TrunkPort.AllVIDs != v2.VLANConfig.TrunkPort.AllVIDs ||
			!generics.EqualSets(v.VLANConfig.TrunkPort.VIDs, v2.VLANConfig.TrunkPort.VIDs) {
			return false
		}
	} else {
		if v.VLANConfig.AccessPort.VID != v2.VLANConfig.AccessPort.VID {
			return false
		}
	}
	return v.BridgeIfName == v2.BridgeIfName &&
		v.BridgePort == v2.BridgePort
}

// External returns false.
func (v VLANPort) External() bool {
	return false
}

// String describes VLANPort.
func (v VLANPort) String() string {
	var bridgePort string
	if v.BridgePort.UplinkIfName != "" {
		bridgePort = fmt.Sprintf("uplinkIfName: %s", v.BridgePort.UplinkIfName)
	}
	if v.BridgePort.VIFIfName != "" {
		bridgePort = fmt.Sprintf("vifIfName: %s", v.BridgePort.VIFIfName)
	}
	var vlanConfig string
	if v.VLANConfig.TrunkPort != nil {
		vlanConfig = fmt.Sprintf("trunkPort: {allVIDs: %t, vids:%v}",
			v.VLANConfig.TrunkPort.AllVIDs, v.VLANConfig.TrunkPort.VIDs)
	}
	if v.VLANConfig.AccessPort != nil {
		vlanConfig = fmt.Sprintf("accessPort: {vid: %d}", v.VLANConfig.AccessPort.VID)
	}
	return fmt.Sprintf("VLANPort: {bridgeIfName: %s, %s, %s}",
		v.BridgeIfName, bridgePort, vlanConfig)
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
	if v.BridgePort.VIFIfName != "" {
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: generic.VIFTypename,
				ItemName: v.BridgePort.VIFIfName,
			},
			MustSatisfy: func(item dg.Item) bool {
				vif, isVIF := item.(generic.VIF)
				if !isVIF {
					// unreachable
					return false
				}
				return vif.MasterIfName == v.BridgeIfName
			},
			Description: "VIF must exist and it must be bridged",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	} else if v.BridgePort.UplinkIfName != "" {
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: generic.UplinkTypename,
				ItemName: v.BridgePort.UplinkIfName,
			},
			MustSatisfy: func(item dg.Item) bool {
				uplink, isUplink := item.(generic.Uplink)
				if !isUplink {
					// unreachable
					return false
				}
				return uplink.MasterIfName == v.BridgeIfName
			},
			Description: "Uplink must exist and it must be bridged",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	}
	return deps
}

func (v VLANPort) portIfName() string {
	if v.BridgePort.VIFIfName != "" {
		return v.BridgePort.VIFIfName
	}
	if v.BridgePort.UplinkIfName != "" {
		return v.BridgePort.UplinkIfName
	}
	return ""
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

func (c *VLANPortConfigurator) createOrDelete(item dg.Item, del bool) error {
	vlanPort, isVLANPort := item.(VLANPort)
	if !isVLANPort {
		return fmt.Errorf("invalid item type %T, expected VLANPort", item)
	}
	link, err := netlink.LinkByName(vlanPort.portIfName())
	if err != nil {
		// Dependencies should prevent this.
		err = fmt.Errorf("failed to get link for bridge port %s: %w",
			vlanPort.portIfName(), err)
		c.Log.Error(err)
		return err
	}
	if vlanPort.VLANConfig.TrunkPort != nil {
		isTrunk := true
		if vlanPort.VLANConfig.TrunkPort.AllVIDs {
			for vid := firstValidVID; vid <= lastValidVID; vid++ {
				err = c.setVIDForPort(link, vid, isTrunk, del)
				if err != nil {
					return err
				}
			}
		} else {
			for _, vid := range vlanPort.VLANConfig.TrunkPort.VIDs {
				err = c.setVIDForPort(link, vid, isTrunk, del)
				if err != nil {
					return err
				}
			}
		}
	} else if vlanPort.VLANConfig.AccessPort != nil {
		isTrunk := false
		vid := vlanPort.VLANConfig.AccessPort.VID
		err = c.setVIDForPort(link, vid, isTrunk, del)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *VLANPortConfigurator) setVIDForPort(link netlink.Link,
	vid uint16, trunk, del bool) (err error) {
	pvid := !trunk
	untagged := !trunk
	const self = false
	const master = false
	if del {
		err = netlink.BridgeVlanDel(link, vid, pvid, untagged, self, master)
	} else {
		err = netlink.BridgeVlanAdd(link, vid, pvid, untagged, self, master)
	}
	if err != nil {
		portType := "access"
		if trunk {
			portType = "trunk"
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
