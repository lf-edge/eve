// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/vishvananda/netlink"
)

// SrcIPRule : IP rule for source-based IP routing.
type SrcIPRule struct {
	// AdapterLL : Adapter's logical label.
	AdapterLL     string
	AdapterIfName string
	IPAddr        net.IP
	Priority      int
}

// Name combines interface name with the IP address to construct
// a unique identifier for the src IP rule.
func (r SrcIPRule) Name() string {
	return fmt.Sprintf("%s/%s", r.AdapterIfName, r.IPAddr.String())
}

// Label is more human-readable than name.
func (r SrcIPRule) Label() string {
	return fmt.Sprintf("IP rule for %s/%s", r.AdapterLL, r.IPAddr.String())
}

// Type of the item.
func (r SrcIPRule) Type() string {
	return SrcIPRuleTypename
}

// Equal is a comparison method for two equally-named src-IP-rule instances.
func (r SrcIPRule) Equal(other depgraph.Item) bool {
	r2 := other.(SrcIPRule)
	return r.Priority == r2.Priority
}

// External returns false.
func (r SrcIPRule) External() bool {
	return false
}

// String describes source-based IP rule.
func (r SrcIPRule) String() string {
	return fmt.Sprintf("Source-based IP rule: "+
		"{adapter: %s, ifName: %s, ip: %s, prio: %d}",
		r.AdapterLL, r.AdapterIfName, r.IPAddr, r.Priority)
}

// Dependencies lists the referenced adapter as the only dependency.
// This dependency is not actually necessary.
// IP rule can be configured even if the adapter is missing.
func (r SrcIPRule) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterTypename,
				ItemName: r.AdapterIfName,
			},
			Description: "Not strictly necessary",
		},
	}
}

// SrcIPRuleConfigurator implements Configurator interface (libs/reconciler) for IP Rules.
type SrcIPRuleConfigurator struct {
	Log            *base.LogObject
	NetworkMonitor netmonitor.NetworkMonitor
}

// Create adds the source-based IP rule.
func (c *SrcIPRuleConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	rule := item.(SrcIPRule)
	netlinkRule, err := c.makeNetlinkRule(rule)
	if err != nil {
		return err
	}
	return netlink.RuleAdd(netlinkRule)
}

func (c *SrcIPRuleConfigurator) makeNetlinkRule(rule SrcIPRule) (*netlink.Rule, error) {
	r := netlink.NewRule()
	ifIdx, exists, err := c.NetworkMonitor.GetInterfaceIndex(rule.AdapterIfName)
	if !exists {
		// Dependencies should prevent this.
		err := fmt.Errorf("missing interface %s", rule.AdapterIfName)
		c.Log.Error()
		return nil, err
	}
	if err != nil {
		err := fmt.Errorf("GetInterfaceIndex(%s) failed: %v",
			rule.AdapterIfName, err)
		c.Log.Error()
		return nil, err
	}
	r.Table = devicenetwork.DPCBaseRTIndex + ifIdx
	r.Priority = rule.Priority
	r.Family = devicenetwork.HostFamily(rule.IPAddr)
	r.Src = devicenetwork.HostSubnet(rule.IPAddr)
	return r, nil
}

// Modify is not implemented.
func (c *SrcIPRuleConfigurator) Modify(_ context.Context, _, _ depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes the source-based IP rule.
func (c *SrcIPRuleConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	rule := item.(SrcIPRule)
	netlinkRule, err := c.makeNetlinkRule(rule)
	if err != nil {
		return err
	}
	return netlink.RuleDel(netlinkRule)
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *SrcIPRuleConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
