// Copyright (c) 2024 Zededa, Inc.
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
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// BridgePort : network interface added into a Linux bridge.
type BridgePort struct {
	// BridgeIfName : interface name of the bridge.
	BridgeIfName string
	// Variant : port should be one of the supported variants.
	Variant BridgePortVariant
	// True if the action of bridging the port is done outside zedrouter.
	ExternallyBridged bool
	// MTU : Maximum transmission unit size.
	MTU uint16
}

// BridgePortVariant is like union, only one option should have non-zero value.
type BridgePortVariant struct {
	// PortIfName : bridged device network port.
	PortIfName string
	// VIFIfName : bridged VIF.
	VIFIfName string
	// VLANSubinterface : VLAN sub-interface.
	VLANSubinterface *VLANSubinterface
}

// BridgePortName combines bridge name and the interface name of the bridged port
// to construct a unique BridgePort ID.
func BridgePortName(bridgeIfName, portIfName string) string {
	return fmt.Sprintf("%s/%s", bridgeIfName, portIfName)
}

// Name uses BridgePortName to get unique BridgePort ID.
func (p BridgePort) Name() string {
	return BridgePortName(p.BridgeIfName, p.portIfName())
}

// Label for BridgePort.
func (p BridgePort) Label() string {
	return fmt.Sprintf("add port %s into bridge %s", p.portIfName(), p.BridgeIfName)
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
	return fmt.Sprintf("BridgePort: {bridgeIfName: %s, portIfName: %s, "+
		"externallyBridged: %t, MTU: %d}",
		p.BridgeIfName, p.portIfName(), p.ExternallyBridged, p.MTU)
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
	switch {
	case p.Variant.VIFIfName != "":
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: VIFTypename,
				ItemName: p.Variant.VIFIfName,
			},
			Description: "VIF must exist",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	case p.Variant.PortIfName != "":
		var mustSatisfy func(item dg.Item) bool
		if p.ExternallyBridged {
			// Bridging is actually done outside zedrouter (e.g. in NIM).
			// BridgePort is only used for dependency purposes in this case
			// (VLANPort and BPDUGuard depend on BridgePort).
			mustSatisfy = func(item dg.Item) bool {
				port, isPort := item.(generic.Port)
				if !isPort {
					// unreachable
					return false
				}
				return port.MasterIfName == p.BridgeIfName
			}
		}
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: generic.PortTypename,
				ItemName: p.Variant.PortIfName,
			},
			MustSatisfy: mustSatisfy,
			Description: "Port must exist, and if it is managed by NIM, " +
				"it must already be bridged",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	case p.Variant.VLANSubinterface != nil:
		var mustSatisfy func(item dg.Item) bool
		// Note: p.ExternallyBridged is always true in this case.
		// VLAN subinterface is created outside zedrouter (in NIM).
		// BridgePort is only used for dependency purposes in this case
		// (VLANPort and BPDUGuard depend on BridgePort).
		mustSatisfy = func(item dg.Item) bool {
			vlanSubIf, isVLANSubIf := item.(VLANSubIf)
			if !isVLANSubIf {
				// unreachable
				return false
			}
			return vlanSubIf.ParentIfName == p.BridgeIfName &&
				vlanSubIf.ID == p.Variant.VLANSubinterface.VID
		}
		deps = append(deps, dg.Dependency{
			RequiredItem: dg.ItemRef{
				ItemType: VLANSubIntfTypename,
				ItemName: p.Variant.VLANSubinterface.IfName,
			},
			MustSatisfy: mustSatisfy,
			Description: "VLAN sub-interface must exist",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		})
	}
	return deps
}

func (p BridgePort) portIfName() string {
	switch {
	case p.Variant.VIFIfName != "":
		return p.Variant.VIFIfName
	case p.Variant.PortIfName != "":
		return p.Variant.PortIfName
	case p.Variant.VLANSubinterface != nil:
		return p.Variant.VLANSubinterface.IfName
	}
	return ""
}

// GetMTU returns MTU configured for the bridge port.
func (p BridgePort) GetMTU() uint16 {
	if p.MTU == 0 {
		return types.DefaultMTU
	}
	return p.MTU
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
	if bridgePort.ExternallyBridged {
		// Port bridging is done outside zedrouter, NOOP here.
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
	if link.Attrs().MTU != int(bridgePort.GetMTU()) {
		err = netlink.LinkSetMTU(link, int(bridgePort.GetMTU()))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for interface %s: %w",
				bridgePort.GetMTU(), bridgePort.portIfName(), err)
			c.Log.Error(err)
			return err
		}
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

// Modify is able to change the MTU of the port.
func (c *BridgePortConfigurator) Modify(_ context.Context, _, newItem dg.Item) (err error) {
	bridgePort, isBridgePort := newItem.(BridgePort)
	if !isBridgePort {
		return fmt.Errorf("invalid item type %T, expected BridgePort", newItem)
	}
	if bridgePort.ExternallyBridged {
		// Port bridging is done outside zedrouter, NOOP here.
		return nil
	}
	link, err := netlink.LinkByName(bridgePort.portIfName())
	if err != nil {
		err = fmt.Errorf("failed to get link for interface %s: %w",
			bridgePort.portIfName(), err)
		c.Log.Error(err)
		return err
	}
	if link.Attrs().MTU != int(bridgePort.GetMTU()) {
		err = netlink.LinkSetMTU(link, int(bridgePort.GetMTU()))
		if err != nil {
			err = fmt.Errorf("failed to set MTU %d for interface %s: %w",
				bridgePort.GetMTU(), bridgePort.portIfName(), err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
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
	if bridgePort.ExternallyBridged {
		// Port bridging is done outside zedrouter, NOOP here.
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
	if link.Attrs().MTU != types.DefaultMTU {
		err = netlink.LinkSetMTU(link, types.DefaultMTU)
		if err != nil {
			err = fmt.Errorf("failed to set default MTU %d for interface %s: %w",
				types.DefaultMTU, bridgePort.portIfName(), err)
			c.Log.Error(err)
			return err
		}
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

// NeedsRecreate returns false if only MTU changed.
// MTU can be changed without re-creating the bridge port.
func (c *BridgePortConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	oldCfg, isBridgePort := oldItem.(BridgePort)
	if !isBridgePort {
		// unreachable
		return false
	}
	newCfg, isBridgePort := newItem.(BridgePort)
	if !isBridgePort {
		// unreachable
		return false
	}
	return oldCfg.ExternallyBridged != newCfg.ExternallyBridged
}
