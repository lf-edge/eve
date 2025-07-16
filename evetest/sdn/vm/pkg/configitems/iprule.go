// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/lf-edge/eve-libs/depgraph"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// IPRule : IP rule used to select routing table for a given traffic.
type IPRule struct {
	SrcNet   *net.IPNet
	DstNet   *net.IPNet
	Table    int
	Priority int
}

// Name returns the name of the IP rule item.
func (r IPRule) Name() string {
	if r.SrcNet == nil {
		return fmt.Sprintf("%v/to/%d", r.DstNet, r.Table)
	}
	if r.DstNet == nil {
		return fmt.Sprintf("%v/from/%d", r.SrcNet, r.Table)
	}
	return fmt.Sprintf("%v/from/%v/to/%d", r.SrcNet, r.DstNet, r.Table)
}

// Label returns the label of the IP rule item.
func (r IPRule) Label() string {
	if r.SrcNet == nil {
		return fmt.Sprintf("To %v use table %d with prio %d",
			r.DstNet, r.Table, r.Priority)
	}
	if r.DstNet == nil {
		return fmt.Sprintf("From %v use table %d with prio %d",
			r.SrcNet, r.Table, r.Priority)
	}
	return fmt.Sprintf("From %v to %v use table %d with prio %d",
		r.SrcNet, r.DstNet, r.Table, r.Priority)
}

// Type returns the typename of the IP rule item.
func (r IPRule) Type() string {
	return IPRuleTypename
}

// Equal is a comparison method for two equally-named IP-rule instances.
func (r IPRule) Equal(other depgraph.Item) bool {
	r2 := other.(IPRule)
	// Every other attribute is part of the name.
	return r.Priority == r2.Priority
}

// External returns false.
func (r IPRule) External() bool {
	return false
}

// String describes IP rule.
func (r IPRule) String() string {
	return fmt.Sprintf("IP Rule: %#+v", r)
}

// Dependencies return nil (no dependencies).
func (r IPRule) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

// IPRuleConfigurator implements Configurator interface for IP Rules.
type IPRuleConfigurator struct{}

// Create adds IP rule.
func (c *IPRuleConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	rule := item.(IPRule)
	netlinkRule := c.makeNetlinkRule(rule)
	err := netlink.RuleAdd(netlinkRule)
	if err != nil {
		err = fmt.Errorf("failed to add IP rule %+v: %w", netlinkRule, err)
		log.Error(err)
		return err
	}
	return nil
}

func (c *IPRuleConfigurator) makeNetlinkRule(rule IPRule) *netlink.Rule {
	r := netlink.NewRule()
	r.Src = rule.SrcNet
	r.Dst = rule.DstNet
	r.Table = rule.Table
	r.Priority = rule.Priority
	r.Family = syscall.AF_INET
	if rule.SrcNet != nil && len(rule.SrcNet.IP) == net.IPv6len {
		r.Family = syscall.AF_INET6
	}
	if rule.DstNet != nil && len(rule.DstNet.IP) == net.IPv6len {
		r.Family = syscall.AF_INET6
	}
	return r
}

// Modify is not implemented.
func (c *IPRuleConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes IP rule.
func (c *IPRuleConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	rule := item.(IPRule)
	netlinkRule := c.makeNetlinkRule(rule)
	err := netlink.RuleDel(netlinkRule)
	if err != nil {
		err = fmt.Errorf("failed to delete IP rule %+v: %w", netlinkRule, err)
		log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *IPRuleConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
