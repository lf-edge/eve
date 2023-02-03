// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"net"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

const (
	// BaseRTIndex : base index for per-interface routing tables.
	// Routing table ID is a sum of the base with the interface index.
	BaseRTIndex = 500
	// PbrLocalDestPrio : IP rule priority for packets destined to locally owned addresses
	PbrLocalDestPrio = 12000
	// PbrLocalOrigPrio : IP rule priority for locally generated packets
	PbrLocalOrigPrio = 15000
	// PbrNatOutGatewayPrio : IP rule priority for packets destined to gateway(bridge ip) coming from apps.
	PbrNatOutGatewayPrio = 9999
	// PbrNatOutPrio : IP rule priority for packets destined to internet coming from apps
	PbrNatOutPrio = 10000
	// PbrNatInPrio : IP rule priority for external packets coming in towards apps
	PbrNatInPrio = 11000
)

// ===== Manage routes in a particular table.
// See also pbr_linux.go

// FlushRoutesTable removes all routes from this table.
// If ifindex is non-zero we also compare it
func FlushRoutesTable(log *base.LogObject, table int, ifindex int) {
	filter := netlink.Route{Table: table, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	if ifindex != 0 {
		fflags |= netlink.RT_FILTER_OIF
	}
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Errorf("FlushRoutesTable: for table %d, ifindex %d failed, error %v", table, ifindex, err)
		return
	}
	log.Tracef("FlushRoutesTable(%d, %d) - got %d",
		table, ifindex, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		log.Functionf("FlushRoutesTable(%d, %d) deleting %v",
			table, ifindex, rt)
		if err := netlink.RouteDel(&rt); err != nil {
			log.Errorf("FlushRoutesTable - RouteDel %v failed %s",
				rt, err)
		}
	}
}

// ==== manage the ip rules

// FlushRules removes any rules we created for this ifindex
func FlushRules(log *base.LogObject, ifindex int) {
	rules, err := netlink.RuleList(syscall.AF_UNSPEC)
	if err != nil {
		log.Errorf("FlushRules: for ifindex %d failed, error %v", ifindex, err)
		return
	}
	log.Tracef("FlushRules(%d) - got %d", ifindex, len(rules))
	for _, r := range rules {
		if r.Table != BaseRTIndex+ifindex {
			continue
		}
		log.Functionf("FlushRules: RuleDel %v", r)
		if err := netlink.RuleDel(&r); err != nil {
			log.Errorf("FlushRules - RuleDel %v failed %s",
				r, err)
		}
	}
}

func makeSrcNetlinkRule(ifindex int, p net.IPNet, addForSubnet bool, prio int) *netlink.Rule {
	r := netlink.NewRule()
	r.Table = BaseRTIndex + ifindex
	r.Priority = prio
	r.Family = HostFamily(p.IP)

	var subnet net.IPNet
	if addForSubnet {
		subnet = p
	} else {
		subnet = HostSubnet(p.IP)
	}
	r.Src = &subnet

	return r
}

func makeDstLocalNetlinkRule(subnet net.IPNet, gateway net.IP, prio int) *netlink.Rule {
	r := netlink.NewRule()
	r.Table = syscall.RT_TABLE_LOCAL
	r.Priority = prio
	r.Family = HostFamily(gateway)

	r.Src = &subnet
	var g net.IPNet
	g = HostSubnet(gateway)
	r.Dst = &g

	return r
}

func makeDstNetlinkRule(ifindex int, p net.IPNet, addForSubnet bool, prio int) *netlink.Rule {
	r := netlink.NewRule()
	r.Table = BaseRTIndex + ifindex
	r.Priority = prio
	r.Family = HostFamily(p.IP)

	var subnet net.IPNet
	if addForSubnet {
		subnet = p
	} else {
		subnet = HostSubnet(p.IP)
	}
	r.Dst = &subnet

	return r
}

// AddSourceRule create a pbr rule for the address or subet which refers to the
// specific table for the ifindex.
func AddSourceRule(log *base.LogObject, ifindex int, p net.IPNet,
	addForSubnet bool, prio int) {

	log.Functionf("AddSourceRule(%d, %v, %v)", ifindex, p.String(), addForSubnet)
	r := makeSrcNetlinkRule(ifindex, p, addForSubnet, prio)
	log.Tracef("AddSourceRule: RuleAdd %v", r)
	// Avoid duplicate rules
	_ = netlink.RuleDel(r)
	if err := netlink.RuleAdd(r); err != nil {
		log.Errorf("RuleAdd %v failed with %s", r, err)
		return
	}
}

// AddGatewaySourceRule : Rule to match packets destined to brdige IP from apps
func AddGatewaySourceRule(log *base.LogObject, p net.IPNet, gateway net.IP, prio int) {
	log.Functionf("AddGatewaySourceRule(%v, %v)", p.String(), gateway)
	r := makeDstLocalNetlinkRule(p, gateway, prio)
	log.Tracef("AddGatewaySourceRule: RuleAdd %v", r)
	// Avoid duplicate rules
	_ = netlink.RuleDel(r)
	if err := netlink.RuleAdd(r); err != nil {
		log.Errorf("AddGatewaySourceRule: RuleAdd %v failed with %s", r, err)
		return
	}
}

// AddInwardSourceRule : Rule to match port mapped packets going towards apps
func AddInwardSourceRule(log *base.LogObject, ifindex int, p net.IPNet,
	addForSubnet bool, prio int) {

	log.Functionf("AddSourceRule(%d, %v, %v)", ifindex, p.String(), addForSubnet)
	r := makeDstNetlinkRule(ifindex, p, addForSubnet, prio)
	log.Tracef("AddSourceRule: RuleAdd %v", r)
	// Avoid duplicate rules
	_ = netlink.RuleDel(r)
	if err := netlink.RuleAdd(r); err != nil {
		log.Errorf("RuleAdd %v failed with %s", r, err)
		return
	}
}

// DelSourceRule removes the pbr rule for the address or subet which refers to the
// specific table for the ifindex.
func DelSourceRule(log *base.LogObject, ifindex int, p net.IPNet,
	addForSubnet bool, prio int) {

	log.Functionf("DelSourceRule(%d, %v, %v)", ifindex, p.String(), addForSubnet)
	r := makeSrcNetlinkRule(ifindex, p, addForSubnet, prio)
	log.Tracef("DelSourceRule: RuleDel %v", r)
	if err := netlink.RuleDel(r); err != nil {
		log.Errorf("RuleDel %v failed with %s", r, err)
		return
	}
}

// DelGatewaySourceRule :
func DelGatewaySourceRule(log *base.LogObject, p net.IPNet, gateway net.IP, prio int) {
	log.Functionf("DelGatewaySourceRule(%v, %v)", p.String(), gateway)
	r := makeDstLocalNetlinkRule(p, gateway, prio)
	log.Tracef("AddGatewaySourceRule: RuleAdd %v", r)
	if err := netlink.RuleDel(r); err != nil {
		log.Errorf("DelGatewaySourceRule: RuleDel %v failed with %s", r, err)
		return
	}
}

// DelInwardSourceRule :
func DelInwardSourceRule(log *base.LogObject, ifindex int, p net.IPNet,
	addForSubnet bool, prio int) {

	log.Functionf("DelSourceRule(%d, %v, %v)", ifindex, p.String(), addForSubnet)
	r := makeDstNetlinkRule(ifindex, p, addForSubnet, prio)
	log.Tracef("DelSourceRule: RuleDel %v", r)
	if err := netlink.RuleDel(r); err != nil {
		log.Errorf("RuleDel %v failed with %s", r, err)
		return
	}
}
