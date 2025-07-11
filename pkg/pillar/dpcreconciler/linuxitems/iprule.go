// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/vishvananda/netlink"
)

const matchAll = "all"

// IPRule : Linux IP rule.
type IPRule struct {
	Priority int
	Table    int
	// We need to know the IP family of the rule and cannot determine that from
	// Src or Dst because both of those can be nil.
	IPv6 bool
	Src  *net.IPNet
	Dst  *net.IPNet
}

// Name combines all attributes to construct a unique identifier for IP rule.
func (r IPRule) Name() string {
	return fmt.Sprintf("%d/%s/%s/%d", r.Priority,
		r.srcToString(), r.dstToString(), r.Table)
}

// Label is more human-readable than name.
// Label resembles the output of "ip rule list".
func (r IPRule) Label() string {
	return fmt.Sprintf("%d: from %s to %s lookup %d",
		r.Priority, r.srcToString(), r.dstToString(), r.Table)
}

// Type of the item.
func (r IPRule) Type() string {
	if r.IPv6 {
		return IPv6RuleTypename
	}
	return IPv4RuleTypename
}

// Equal compares two IPRule instances.
func (r IPRule) Equal(other dg.Item) bool {
	r2, isIPRule := other.(IPRule)
	if !isIPRule {
		return false
	}
	return r.Priority == r2.Priority &&
		r.Table == r2.Table &&
		r.IPv6 == r2.IPv6 &&
		netutils.EqualIPNets(r.Src, r2.Src) &&
		netutils.EqualIPNets(r.Dst, r2.Dst)
}

// External returns false.
func (r IPRule) External() bool {
	return false
}

// String describes IPRule in detail.
func (r IPRule) String() string {
	version := "v4"
	if r.IPv6 {
		version = "v6"
	}
	return fmt.Sprintf("IP%v rule: "+
		"{prio: %d, Src: %s, Dst: %s, Table: %d}",
		version, r.Priority, r.srcToString(), r.dstToString(), r.Table)
}

// Dependencies returns no dependencies (table does not have to exist).
func (r IPRule) Dependencies() (deps []dg.Dependency) {
	return nil
}

func (r IPRule) srcToString() string {
	src := matchAll
	if r.Src != nil {
		src = r.Src.String()
	}
	return src
}

func (r IPRule) dstToString() string {
	dst := matchAll
	if r.Dst != nil {
		dst = r.Dst.String()
	}
	return dst
}

// Does this overwrites the rule created by default for the Local table?
func (r IPRule) replacesDefaultLocalRule() bool {
	return r.Src == nil && r.Dst == nil && r.Table == unix.RT_TABLE_LOCAL
}

// Get rule installed by default for the Local table.
func getDefaultRule(ipv6 bool) IPRule {
	if ipv6 {
		return IPRule{
			Priority: 0,
			Table:    unix.RT_TABLE_LOCAL,
			IPv6:     true,
			Src:      nil,
			Dst:      nil,
		}
	}
	return IPRule{
		Priority: 0,
		Table:    unix.RT_TABLE_LOCAL,
		Src:      nil,
		Dst:      nil,
	}
}

// IPRuleConfigurator implements Configurator interface (libs/reconciler)
// for Linux IP rule.
type IPRuleConfigurator struct {
	Log *base.LogObject
}

// Create adds IP rule.
func (c *IPRuleConfigurator) Create(ctx context.Context, item dg.Item) error {
	rule, isIPRule := item.(IPRule)
	if !isIPRule {
		return fmt.Errorf("invalid item type %T, expected IPRule", item)
	}
	if rule.replacesDefaultLocalRule() {
		// First remove the default rule for the Local table.
		netlinkRule := c.makeNetlinkRule(getDefaultRule(rule.IPv6))
		err := netlink.RuleDel(netlinkRule)
		if err != nil {
			err = fmt.Errorf("failed to delete default local IP rule %+v: %w",
				netlinkRule, err)
			c.Log.Error(err)
			return err
		}
	}
	netlinkRule := c.makeNetlinkRule(rule)
	err := netlink.RuleAdd(netlinkRule)
	if err != nil {
		err = fmt.Errorf("failed to add IP rule %+v: %w", netlinkRule, err)
		c.Log.Error(err)
		return err
	}
	return nil
}

func (c *IPRuleConfigurator) makeNetlinkRule(rule IPRule) *netlink.Rule {
	r := netlink.NewRule()
	r.Src = rule.Src
	r.Dst = rule.Dst
	r.Table = rule.Table
	r.Priority = rule.Priority
	r.Family = netlink.FAMILY_V4
	if rule.IPv6 {
		r.Family = netlink.FAMILY_V6
	}
	return r
}

// Modify is not implemented.
func (c *IPRuleConfigurator) Modify(_ context.Context, _, _ dg.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes IP rule.
func (c *IPRuleConfigurator) Delete(ctx context.Context, item dg.Item) error {
	rule, isIPRule := item.(IPRule)
	if !isIPRule {
		return fmt.Errorf("invalid item type %T, expected IPRule", item)
	}
	netlinkRule := c.makeNetlinkRule(rule)
	err := netlink.RuleDel(netlinkRule)
	if err != nil {
		err = fmt.Errorf("failed to delete IP rule %+v: %w", netlinkRule, err)
		c.Log.Error(err)
		return err
	}
	if rule.replacesDefaultLocalRule() {
		// Bring back the default rule for the Local table.
		netlinkRule = c.makeNetlinkRule(getDefaultRule(rule.IPv6))
		err = netlink.RuleAdd(netlinkRule)
		if err != nil {
			err = fmt.Errorf("failed to add default local IP rule %+v: %w",
				netlinkRule, err)
			c.Log.Error(err)
			return err
		}
	}
	return nil
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *IPRuleConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
