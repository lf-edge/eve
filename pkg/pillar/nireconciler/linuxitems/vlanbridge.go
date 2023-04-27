// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"time"

	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/vishvananda/netlink"
)

// VLANBridge : VLAN configuration for a Linux bridge.
type VLANBridge struct {
	// BridgeIfName : interface name of the bridge.
	BridgeIfName string
	// EnableVLANFiltering : drop packet if it belongs to a VLAN which is not enabled
	// on the input bridge port (using VLANPort config item).
	EnableVLANFiltering bool
}

// Name returns the interface name of the bridge.
func (v VLANBridge) Name() string {
	return v.BridgeIfName
}

// Label for VLANBridge.
func (v VLANBridge) Label() string {
	return v.BridgeIfName + " (VLAN bridge)"
}

// Type of the item.
func (v VLANBridge) Type() string {
	return VLANBridgeTypename
}

// Equal compares two VLANBridge instances.
func (v VLANBridge) Equal(other dg.Item) bool {
	v2, isVLANBridge := other.(VLANBridge)
	if !isVLANBridge {
		return false
	}
	return v == v2
}

// External returns false.
func (v VLANBridge) External() bool {
	return false
}

// String describes VLANBridge.
func (v VLANBridge) String() string {
	return fmt.Sprintf("VLANBridge: {bridgeIfName: %s, enableVlanFiltering: %t}",
		v.BridgeIfName, v.EnableVLANFiltering)
}

// Dependencies returns the bridge as the only dependency.
func (v VLANBridge) Dependencies() (deps []dg.Dependency) {
	deps = append(deps, dg.Dependency{
		RequiredItem: dg.ItemRef{
			ItemType: BridgeTypename,
			ItemName: v.BridgeIfName,
		},
		Attributes: dg.DependencyAttributes{
			AutoDeletedByExternal: true,
		},
		Description: "Bridge interface must exist",
	})
	return deps
}

// VLANBridgeConfigurator implements Configurator interface (libs/reconciler)
// for VLAN configuration applied to a Linux bridge.
type VLANBridgeConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create applies VLAN configuration to a bridge.
func (c *VLANBridgeConfigurator) Create(ctx context.Context, item dg.Item) error {
	vlanBridge, isVLANBridge := item.(VLANBridge)
	if !isVLANBridge {
		return fmt.Errorf("invalid item type %T, expected VLANBridge", item)
	}
	brIfName := vlanBridge.BridgeIfName
	enableVlanFiltering := vlanBridge.EnableVLANFiltering
	brIsBusy, err := c.setVlanFiltering(brIfName, enableVlanFiltering)
	if err != nil && !brIsBusy {
		c.Log.Error(err)
		return err
	}
	if brIsBusy {
		c.retryInBackground(ctx, brIfName, enableVlanFiltering, err)
	}
	return nil
}

func (c *VLANBridgeConfigurator) setVlanFiltering(
	brIfName string, enable bool) (brIsBusy bool, err error) {
	link, err := netlink.LinkByName(brIfName)
	if err != nil {
		// Dependencies should prevent this.
		return false, fmt.Errorf("failed to get link for bridge %s: %w", brIfName, err)
	}
	bridgeLink, isBridgeLink := link.(*netlink.Bridge)
	if !isBridgeLink {
		return false, fmt.Errorf("link %s is not a bridge", brIfName)
	}
	isEnabled := bridgeLink.VlanFiltering != nil && *bridgeLink.VlanFiltering == true
	if isEnabled == enable {
		// Nothing to change.
		c.Log.Noticef("Bridge %s already has VLAN filtering set to %t",
			brIfName, enable)
		return false, nil
	}
	err = netlink.BridgeSetVlanFiltering(link, enable)
	if err != nil {
		brIsBusy = errors.Is(err, unix.EBUSY)
		return brIsBusy, fmt.Errorf("failed to set VLAN filtering to %t for bridge %s: %w",
			enable, brIfName, err)
	}
	return false, nil
}

// In the past we have seen that for some strange reason enabling/disabling VLAN filtering
// may throw back error stating that the device is busy.
// In such case we will keep retrying for up to 1 minute in the background.
func (c *VLANBridgeConfigurator) retryInBackground(ctx context.Context, brIfName string,
	enableVlanFiltering bool, err error) {
	done := reconciler.ContinueInBackground(ctx)
	deadline := time.Now().Add(time.Minute)
	const delay = time.Second
	go func() {
		for {
			c.Log.Warnf("Getting error '%v' for bridge %s, "+
				"will retry setting VLAN filtering in %v", err, brIfName, delay)
			time.Sleep(delay)
			// Check if it was canceled in the meantime.
			select {
			case <-ctx.Done():
				c.Log.Warnf("Canceling retries to set VLAN filtering for bridge %s, "+
					"context is done", brIfName)
				done(err)
				return
			default:
			}
			// Try to set VLAN filtering again.
			var brIsBusy bool
			brIsBusy, err = c.setVlanFiltering(brIfName, enableVlanFiltering)
			if err == nil {
				done(nil)
				return
			}
			if brIsBusy && time.Now().Before(deadline) {
				continue
			}
			done(err)
			return
		}
	}()
}

// Modify is not implemented.
func (c *VLANBridgeConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes VLAN configuration from a bridge.
func (c *VLANBridgeConfigurator) Delete(ctx context.Context, item dg.Item) error {
	vlanBridge, isVLANBridge := item.(VLANBridge)
	if !isVLANBridge {
		return fmt.Errorf("invalid item type %T, expected VLANBridge", item)
	}
	const enableVlanFiltering = false // default value
	brIfName := vlanBridge.BridgeIfName
	brIsBusy, err := c.setVlanFiltering(brIfName, enableVlanFiltering)
	if err != nil && !brIsBusy {
		c.Log.Error(err)
		return err
	}
	if brIsBusy {
		c.retryInBackground(ctx, brIfName, enableVlanFiltering, err)
	}
	return nil
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *VLANBridgeConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
