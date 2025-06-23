// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"net"

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
	Mark     uint32
	Mask     *uint32
	Src      *net.IPNet
	Dst      *net.IPNet
}

// Name combines all attributes to construct a unique identifier for IP rule.
func (r IPRule) Name() string {
	if r.Mark == 0 || r.Mask == nil {
		return fmt.Sprintf("%d/%s/%s/%d", r.Priority,
			r.srcToString(), r.dstToString(), r.Table)
	}
	return fmt.Sprintf("%d/%s/%s/%x/%x/%d", r.Priority,
		r.srcToString(), r.dstToString(), r.Mark, *r.Mask, r.Table)
}

// Label is more human-readable than name.
// Label resembles the output of "ip rule list".
func (r IPRule) Label() string {
	var mark string
	if r.Mark != 0 && r.Mask != nil {
		mark = fmt.Sprintf(" fwmark %x/%x", r.Mark, *r.Mask)
	}
	return fmt.Sprintf("%d: from %s to %s%s lookup %d",
		r.Priority, r.srcToString(), r.dstToString(), mark, r.Table)
}

// Type of the item.
func (r IPRule) Type() string {
	return IPRuleTypename
}

// Equal compares two IPRule instances.
func (r IPRule) Equal(other dg.Item) bool {
	r2, isIPRule := other.(IPRule)
	if !isIPRule {
		return false
	}
	if r.Mask == nil || r2.Mask == nil {
		if r.Mask != r2.Mask {
			return false
		}
	} else {
		if *r.Mask != *r2.Mask {
			return false
		}
	}
	return r.Priority == r2.Priority &&
		r.Table == r2.Table &&
		r.Mark == r2.Mark &&
		netutils.EqualIPNets(r.Src, r2.Src) &&
		netutils.EqualIPNets(r.Dst, r2.Dst)
}

// External returns false.
func (r IPRule) External() bool {
	return false
}

// String describes IPRule in detail.
func (r IPRule) String() string {
	var mark string
	if r.Mark != 0 && r.Mask != nil {
		mark = fmt.Sprintf(", Mark: %x/%x", r.Mark, *r.Mask)
	}
	return fmt.Sprintf("IP rule: "+
		"{prio: %d, Src: %s, Dst: %s, Table: %d%s}",
		r.Priority, r.srcToString(), r.dstToString(), r.Table, mark)
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
	r.Mark = rule.Mark
	r.Mask = rule.Mask
	r.Priority = rule.Priority
	r.Family = netlink.FAMILY_V4
	if rule.Src != nil && rule.Src.IP.To4() == nil {
		r.Family = netlink.FAMILY_V6
	}
	if rule.Dst != nil && rule.Dst.IP.To4() == nil {
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
	return nil
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *IPRuleConfigurator) NeedsRecreate(oldItem, newItem dg.Item) (recreate bool) {
	return true
}
