// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
)

// BridgePort : network interface added into a Linux bridge.
type BridgePort struct {
	// BridgeIfName : interface name of the bridge.
	BridgeIfName string
	// Variant : port should be one of the supported variants.
	Variant BridgePortVariant
}

// BridgePortVariant is like union, only one option should have non-zero value.
type BridgePortVariant struct {
	// UplinkIfName : bridged uplink interface.
	UplinkIfName string
	// VIFIfName : bridged VIF.
	VIFIfName string
}

// Name returns the interface name of the bridged port
func (p BridgePort) Name() string {
	return p.portIfName()
}

// Label for VLANPort.
func (p BridgePort) Label() string {
	return p.portIfName() + " (bridge port)"
}

// Type of the item.
func (p BridgePort) Type() string {
	return BridgePortTypename
}

// Equal compares two BridgePort instances.
func (p BridgePort) Equal(other dg.Item) bool {
	p2, isBridgePort := other.(BridgePort)
	if !isBridgePort {
		return false
	}
	return p == p2
}

// External returns false.
func (p BridgePort) External() bool {
	return false
}

// String describes BridgePort.
func (p BridgePort) String() string {
	return fmt.Sprintf("BridgePort: {bridgeIfName: %s, portIfName: %s}",
		p.BridgeIfName, p.portIfName())
}

// Dependencies returns the bridge and the port as the dependencies.
func (p BridgePort) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.ItemRef{
			ItemType: BridgeTypename,
			ItemName: p.BridgeIfName,
		},
		Description: "Bridge must exist",
	})
	if p.Variant.VIFIfName != "" {
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: generic.VIFTypename,
				ItemName: p.Variant.VIFIfName,
			},
			Description: "VIF must exist",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	} else if p.Variant.UplinkIfName != "" {
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: generic.UplinkTypename,
				ItemName: p.Variant.UplinkIfName,
			},
			MustSatisfy: func(item dg.Item) bool {
				uplink, isUplink := item.(generic.Uplink)
				if !isUplink {
					// unreachable
					return false
				}
				// Bridging is actually done by NIM for uplink interfaces.
				// BridgePort is only used for dependency purposes in this case
				// (VLANPort depends on BridgePort).
				return uplink.MasterIfName == p.BridgeIfName
			},
			Description: "Uplink must exist and it must be bridged (by NIM)",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	}
	return deps
}

func (p BridgePort) portIfName() string {
	if p.Variant.VIFIfName != "" {
		return p.Variant.VIFIfName
	}
	if p.Variant.UplinkIfName != "" {
		return p.Variant.UplinkIfName
	}
	return ""
}

// BridgePortConfigurator implements Configurator interface (libs/reconciler)
// for Linux bridge port.
type BridgePortConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create attaches port to a bridge.
func (c *BridgePortConfigurator) Create(ctx context.Context, item dg.Item) error {
	bridgePort, isBridgePort := item.(BridgePort)
	if !isBridgePort {
		return fmt.Errorf("invalid item type %T, expected BridgePort", item)
	}
	if bridgePort.Variant.UplinkIfName != "" {
		// NOOP for uplink - NIM is responsible for bridging uplink ports.
		return nil
	}
	link, err := netlink.LinkByName(bridgePort.portIfName())
	if err != nil {
		err = fmt.Errorf("failed to get link for interface %s: %w",
			bridgePort.portIfName(), err)
		c.Log.Error(err)
		return err
	}
	bridge, err := netlink.LinkByName(bridgePort.BridgeIfName)
	if err != nil {
		err = fmt.Errorf("failed to get link for bridge %s: %w",
			bridgePort.BridgeIfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		err = fmt.Errorf("failed to set interface %s UP: %w",
			bridgePort.portIfName(), err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkSetMaster(link, bridge)
	if err != nil {
		err = fmt.Errorf("failed to attach interface %s to bridge %s: %w",
			bridgePort.portIfName(), bridgePort.BridgeIfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *BridgePortConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete detaches port from the bridge.
func (c *BridgePortConfigurator) Delete(ctx context.Context, item dg.Item) (err error) {
	defer func() {
		if err != nil {
			var linkNotFound netlink.LinkNotFoundError
			if errors.As(err, &linkNotFound) {
				// (VIF) Port was already removed (by hypervisor),
				// but we have not yet received netlink notification about the deletion.
				// Ignore the error.
				err = nil
				return
			}
		}
	}()
	bridgePort, isBridgePort := item.(BridgePort)
	if !isBridgePort {
		return fmt.Errorf("invalid item type %T, expected BridgePort", item)
	}
	if bridgePort.Variant.UplinkIfName != "" {
		// NOOP for uplink - NIM is responsible for bridging uplink ports.
		return nil
	}
	link, err := netlink.LinkByName(bridgePort.portIfName())
	if err != nil {
		err = fmt.Errorf("failed to get link for interface %s: %w",
			bridgePort.portIfName(), err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkSetNoMaster(link)
	if err != nil {
		err = fmt.Errorf("failed to detach interface %s from bridge %s: %w",
			bridgePort.portIfName(), bridgePort.BridgeIfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkSetDown(link)
	if err != nil {
		err = fmt.Errorf("failed to set interface %s DOWN: %w",
			bridgePort.portIfName(), err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *BridgePortConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
