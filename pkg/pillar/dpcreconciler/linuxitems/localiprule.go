// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

// LocalIPRule : singleton item representing IP rule for local RT
// This is for both IPv4 and IPv6.
type LocalIPRule struct {
	Priority int
}

// Name returns a constant string - LocalIPRule is a singleton.
func (r LocalIPRule) Name() string {
	return LocalIPRuleTypename
}

// Label is not defined.
func (r LocalIPRule) Label() string {
	return ""
}

// Type of the item.
func (r LocalIPRule) Type() string {
	return LocalIPRuleTypename
}

// Equal only compares the priority to check if it changed.
func (r LocalIPRule) Equal(other depgraph.Item) bool {
	// Not relevant - Modify should never be called for this item.
	r2 := other.(LocalIPRule)
	return r.Priority == r2.Priority
}

// External returns false.
func (r LocalIPRule) External() bool {
	return false
}

// String describes the Local IP rule (priority).
func (r LocalIPRule) String() string {
	return fmt.Sprintf("IP rule for local RT with new priority: %v",
		r.Priority)
}

// Dependencies returns nothing.
func (r LocalIPRule) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// LocalIPRuleConfigurator implements Configurator interface (libs/reconciler) for local IP Rule.
type LocalIPRuleConfigurator struct {
	Log *base.LogObject
}

// Create modifies the priority of the (automatically created) local IP rule.
func (c *LocalIPRuleConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	prio := item.(LocalIPRule).Priority
	// IPv4
	r := netlink.NewRule()
	r.Table = syscall.RT_TABLE_LOCAL
	r.Priority = prio
	r.Family = syscall.AF_INET
	if err := netlink.RuleAdd(r); err != nil {
		err = fmt.Errorf("netlink.RuleAdd %v failed with %s", r, err)
		c.Log.Error(err)
		return err
	}
	r.Priority = 0
	if err := netlink.RuleDel(r); err != nil {
		err = fmt.Errorf("netlink.RuleDel %v failed with %s", r, err)
		c.Log.Error(err)
		return err
	}

	// IPv6
	r.Priority = prio
	r.Family = syscall.AF_INET6
	if err := netlink.RuleAdd(r); err != nil {
		err = fmt.Errorf("netlink.RuleAdd %v failed with %s", r, err)
		c.Log.Error(err)
		return err
	}
	r.Priority = 0
	if err := netlink.RuleDel(r); err != nil {
		err = fmt.Errorf("netlink.RuleDel %v failed with %s", r, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *LocalIPRuleConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete always returns error. NIM never reverts back to the original priority
// of the local IP rule.
func (c *LocalIPRuleConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	return errors.New("not implemented")
}

// NeedsRecreate is not relevant here - neither Modify nor Delete should ever
// be called for this item.
func (c *LocalIPRuleConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return false
}
