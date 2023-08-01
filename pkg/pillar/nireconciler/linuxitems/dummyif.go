// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

// DummyIf : Linux dummy interface.
type DummyIf struct {
	// IfName : name of the DummyIf interface inside the network stack.
	IfName string
	// ARPOff : enable to suppress ARP on the dummy interface.
	ARPOff bool
}

// Name returns the physical interface name.
func (d DummyIf) Name() string {
	return d.IfName
}

// Label is not provided.
func (d DummyIf) Label() string {
	return ""
}

// Type of the item.
func (d DummyIf) Type() string {
	return DummyIfTypename
}

// Equal compares two DummyIf instances.
func (d DummyIf) Equal(other dg.Item) bool {
	d2, isDummyIf := other.(DummyIf)
	if !isDummyIf {
		return false
	}
	return d == d2
}

// External returns false.
func (d DummyIf) External() bool {
	return false
}

// String describes DummyIf.
func (d DummyIf) String() string {
	return fmt.Sprintf("DummyIf: {ifName: %s, arpOff: %t}",
		d.IfName, d.ARPOff)
}

// Dependencies returns no dependencies.
func (d DummyIf) Dependencies() (deps []dg.Dependency) {
	return nil
}

// DummyIfConfigurator implements Configurator interface (libs/reconciler)
// for Linux dummy interface.
type DummyIfConfigurator struct {
	Log *base.LogObject
}

// Create adds new Linux dummy interface.
func (c *DummyIfConfigurator) Create(ctx context.Context, item dg.Item) error {
	dummyIf, isDummyIf := item.(DummyIf)
	if !isDummyIf {
		return fmt.Errorf("invalid item type %T, expected DummyIf", item)
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = dummyIf.IfName
	netlinkDummy := &netlink.Dummy{LinkAttrs: attrs}
	if err := netlink.LinkAdd(netlinkDummy); err != nil {
		err = fmt.Errorf("failed to add dummy interface %s: %w", dummyIf.IfName, err)
		c.Log.Error(err)
		return err
	}
	if err := netlink.LinkSetUp(netlinkDummy); err != nil {
		err = fmt.Errorf("failed to set dummy interface %s UP: %w", dummyIf.IfName, err)
		c.Log.Error(err)
		return err
	}
	if dummyIf.ARPOff {
		if err := netlink.LinkSetARPOff(netlinkDummy); err != nil {
			err = fmt.Errorf("failed to set ARP off for dummy interface %s: %w",
				dummyIf.IfName, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// Modify is not implemented.
func (c *DummyIfConfigurator) Modify(ctx context.Context, oldItem, newItem dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes Linux dummy interface.
func (c *DummyIfConfigurator) Delete(ctx context.Context, item dg.Item) error {
	dummyIf, isDummyIf := item.(DummyIf)
	if !isDummyIf {
		return fmt.Errorf("invalid item type %T, expected DummyIf", item)
	}
	link, err := netlink.LinkByName(dummyIf.IfName)
	if err != nil {
		err = fmt.Errorf("failed to select dummy interface %s for removal: %w",
			dummyIf.IfName, err)
		c.Log.Error(err)
		return err
	}
	err = netlink.LinkDel(link)
	if err != nil {
		err = fmt.Errorf("failed to delete dummy interface %s: %w", dummyIf.IfName, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *DummyIfConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
