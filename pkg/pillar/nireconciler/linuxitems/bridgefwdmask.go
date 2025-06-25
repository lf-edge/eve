// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"os"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	groupFwdMaskPathTemplate = "/sys/class/net/%s/bridge/group_fwd_mask"

	// Bits correspond to the last hex digit of MAC addresses
	bitEAPOL = 1 << 3  // 0x0008, 01-80-C2-00-00-03
	bitMVRP  = 1 << 13 // 0x2000, 01-80-C2-00-00-0D
	bitLLDP  = 1 << 14 // 0x4000, 01-80-C2-00-00-0E
)

// BridgeFwdMask defines which Ethernet control protocol frames should be forwarded
// by a Linux bridge via the group_fwd_mask setting in /sys/class/net/<bridge>/bridge/.
// Only includes protocols that are permitted to be forwarded by the Linux kernel,
// excluding those restricted due to reserved multicast MAC address handling.
type BridgeFwdMask struct {
	// BridgeIfName is the interface name of the Linux bridge.
	BridgeIfName string

	// ForwardLLDP enables forwarding of LLDP (802.1AB) frames (EtherType 0x88cc,
	// destination MAC 01-80-C2-00-00-0E).
	ForwardLLDP bool

	// ForwardEAPOL enables forwarding of EAPOL (802.1X authentication) frames
	// (EtherType 0x888e, destination MAC 01-80-C2-00-00-03).
	// Note: currently not configurable via EVE API (i.e. always disabled).
	ForwardEAPOL bool

	// ForwardMVRP enables forwarding of Multiple VLAN Registration Protocol (802.1AK)
	// frames (destination MAC 01-80-C2-00-00-0D).
	// Note: currently not configurable via EVE API (i.e. always disabled).
	ForwardMVRP bool
}

// Name returns the interface name of the bridge
// (there can be only one instance of BridgeFwdMask for each bridge).
func (m BridgeFwdMask) Name() string {
	return m.BridgeIfName
}

// Label for BridgeFwdMask.
func (m BridgeFwdMask) Label() string {
	return m.BridgeIfName + " (Forwarding mask)"
}

// Type of the item.
func (m BridgeFwdMask) Type() string {
	return BridgeFwdMaskTypename
}

// Equal compares two BridgeFwdMask instances.
func (m BridgeFwdMask) Equal(other dg.Item) bool {
	m2, isBridgeFwdMask := other.(BridgeFwdMask)
	if !isBridgeFwdMask {
		return false
	}
	return m == m2
}

// External returns false.
func (m BridgeFwdMask) External() bool {
	return false
}

// String describes BridgeFwdMask.
func (m BridgeFwdMask) String() string {
	return fmt.Sprintf("BridgeFwdMask: {bridgeIfName: %s, forwardLLDP: %t, "+
		"forwardEAPOL: %t, forwardMVRP: %t}",
		m.BridgeIfName, m.ForwardLLDP, m.ForwardEAPOL, m.ForwardMVRP)
}

// Dependencies returns the bridge as the only dependency.
func (m BridgeFwdMask) Dependencies() (deps []dg.Dependency) {
	return []dg.Dependency{
		{
			RequiredItem: dg.ItemRef{
				ItemType: BridgeTypename,
				ItemName: m.BridgeIfName,
			},
			Description: "Bridge must exist",
			Attributes: dg.DependencyAttributes{
				AutoDeletedByExternal: true,
			},
		},
	}
}

// toMaskValue returns the hex string (e.g. "0x4008") representing the forwarding mask
func (m BridgeFwdMask) toMaskValue() string {
	var mask uint32
	if m.ForwardMVRP {
		mask |= bitMVRP
	}
	if m.ForwardEAPOL {
		mask |= bitEAPOL
	}
	if m.ForwardLLDP {
		mask |= bitLLDP
	}
	return fmt.Sprintf("0x%X", mask)
}

// BridgeFwdMaskConfigurator implements Configurator interface (libs/reconciler)
// for Linux bridge forwarding mask.
type BridgeFwdMaskConfigurator struct {
	Log *base.LogObject
}

// Create sets the Linux bridge forwarding mask.
func (c *BridgeFwdMaskConfigurator) Create(ctx context.Context, item dg.Item) error {
	fwdMask, ok := item.(BridgeFwdMask)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected BridgeFwdMask", item)
	}
	fwdMaskVal := fwdMask.toMaskValue()
	fwdMaskPath := fmt.Sprintf(groupFwdMaskPathTemplate, fwdMask.BridgeIfName)
	if err := os.WriteFile(fwdMaskPath, []byte(fwdMaskVal), 0644); err != nil {
		return fmt.Errorf("failed to set forwarding mask for bridge %s: %w",
			fwdMask.BridgeIfName, err)
	}
	return nil
}

// Modify is not implemented.
func (c *BridgeFwdMaskConfigurator) Modify(_ context.Context, _, _ dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete zeroes-out the forwarding mask for the bridge.
func (c *BridgeFwdMaskConfigurator) Delete(ctx context.Context, item dg.Item) error {
	fwdMask, ok := item.(BridgeFwdMask)
	if !ok {
		return fmt.Errorf("invalid item type %T, expected BridgeFwdMask", item)
	}
	fwdMaskVal := "0x0"
	fwdMaskPath := fmt.Sprintf(groupFwdMaskPathTemplate, fwdMask.BridgeIfName)
	if err := os.WriteFile(fwdMaskPath, []byte(fwdMaskVal), 0644); err != nil {
		return fmt.Errorf("failed to zero-out forwarding mask for bridge %s: %w",
			fwdMask.BridgeIfName, err)
	}
	return nil
}

// NeedsRecreate returns true - Modify method is not implemented.
func (c *BridgeFwdMaskConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
