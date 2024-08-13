// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"os"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
)

// BPDUGuard : item representing BPDU guard enabled on a Linux bridge port.
// BPDU Guard is a feature that defends the Layer 2 Spanning Tree Protocol (STP) topology
// against BPDU-related threats and is designed to protect the switching network.
// The BPDU guard feature must be activated on ports that should not receive BPDUs from
// connected devices.
type BPDUGuard struct {
	// BridgeIfName : interface name of the bridge.
	BridgeIfName string
	// PortIfName : interface name of the bridge port.
	PortIfName string
	// ForVIF : true if this is BPDU guard applied to application VIF
	// (and not to device network port).
	ForVIF bool
}

// Name returns the interface name of the bridged port
// It is unique identifier because there can be at most one instance of BPDUGuard
// associated with a given bridged port.
func (g BPDUGuard) Name() string {
	return g.PortIfName
}

// Label for BPDUGuard.
func (g BPDUGuard) Label() string {
	return g.PortIfName + " (BPDU guard)"
}

// Type of the item.
func (g BPDUGuard) Type() string {
	return BPDUGuardTypename
}

// Equal compares two equally-named BPDUGuard instances.
func (g BPDUGuard) Equal(other dg.Item) bool {
	g2, isBPDUGuard := other.(BPDUGuard)
	if !isBPDUGuard {
		return false
	}
	return g.BridgeIfName == g2.BridgeIfName && g.ForVIF == g2.ForVIF
}

// External returns false.
func (g BPDUGuard) External() bool {
	return false
}

// String describes BPDUGuard.
func (g BPDUGuard) String() string {
	return fmt.Sprintf("BPDUGuard: {bridgeIfName: %s, portIfName: %s, forVIF: %t}",
		g.BridgeIfName, g.PortIfName, g.ForVIF)
}

// Dependencies returns the bridge and the port as the dependencies.
func (g BPDUGuard) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.ItemRef{
			ItemType: BridgeTypename,
			ItemName: g.BridgeIfName,
		},
		Description: "Bridge must exist",
		Attributes: dg.DependencyAttributes{
			AutoDeletedByExternal: true,
		},
	})
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.ItemRef{
			ItemType: BridgePortTypename,
			ItemName: g.PortIfName,
		},
		MustSatisfy: func(item dg.Item) bool {
			bridgePort, isBridgePort := item.(BridgePort)
			if !isBridgePort {
				// unreachable
				return false
			}
			return bridgePort.BridgeIfName == g.BridgeIfName
		},
		Description: "Port must be attached to the bridge",
	})
	return deps
}

// BPDUGuardConfigurator implements Configurator interface (libs/reconciler)
// for BPDU guard applied to a Linux bridge port.
type BPDUGuardConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create enables BPDU guard on a bridge port.
func (c *BPDUGuardConfigurator) Create(ctx context.Context, item dg.Item) error {
	return c.createOrDelete(item, false)
}

func (c *BPDUGuardConfigurator) createOrDelete(item dg.Item, del bool) (err error) {
	bpduGuard, isBPDUGuard := item.(BPDUGuard)
	if !isBPDUGuard {
		return fmt.Errorf("invalid item type %T, expected BPDUGuard", item)
	}
	sysOptVal := "1"
	action := "enable"
	if del {
		sysOptVal = "0"
		action = "disable"
	}
	sysOptPath := fmt.Sprintf("/sys/class/net/%s/brif/%s/bpdu_guard",
		bpduGuard.BridgeIfName, bpduGuard.PortIfName)
	err = os.WriteFile(sysOptPath, []byte(sysOptVal), 0644)
	if err != nil {
		if del && errors.Is(err, os.ErrNotExist) {
			// Port was already removed (by hypervisor or domainmgr),
			// but we have not yet received netlink notification about the deletion.
			// Ignore the error.
			return nil
		}
		err = fmt.Errorf("failed to %s BPDU guard for port %s on bridge %s: %w",
			action, bpduGuard.PortIfName, bpduGuard.BridgeIfName, err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *BPDUGuardConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes BPDU guard from a bridge port.
func (c *BPDUGuardConfigurator) Delete(ctx context.Context, item dg.Item) error {
	return c.createOrDelete(item, true)
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *BPDUGuardConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
