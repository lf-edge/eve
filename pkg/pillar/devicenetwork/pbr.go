// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"net"
	"syscall"

	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
)

const baseTableIndex = 500

// ===== Manage routes in a particular table.
// See also pbr_linux.go

// FlushRoutesTable removes all rules from this table.
// If ifindex is non-zero we also compare it
func FlushRoutesTable(table int, ifindex int) {
	filter := netlink.Route{Table: table, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	if ifindex != 0 {
		fflags |= netlink.RT_FILTER_OIF
	}
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatalf("RouteList failed: %v", err)
	}
	log.Debugf("FlushRoutesTable(%d, %d) - got %d",
		table, ifindex, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		log.Debugf("FlushRoutesTable(%d, %d) deleting %v",
			table, ifindex, rt)
		if err := netlink.RouteDel(&rt); err != nil {
			log.Errorf("FlushRoutesTable - RouteDel %v failed %s",
				rt, err)
		}
	}
}

// ==== manage the ip rules

// FlushRules removes any rules we created for this ifindex
func FlushRules(ifindex int) {
	rules, err := netlink.RuleList(syscall.AF_UNSPEC)
	if err != nil {
		log.Fatalf("RuleList failed: %v", err)
	}
	log.Debugf("FlushRules(%d) - got %d", ifindex, len(rules))
	for _, r := range rules {
		if r.Table != baseTableIndex+ifindex {
			continue
		}
		log.Infof("FlushRules: RuleDel %v", r)
		if err := netlink.RuleDel(&r); err != nil {
			log.Fatalf("FlushRules - RuleDel %v failed %s",
				r, err)
		}
	}
}

func makeNetlinkRule(ifindex int, p net.IPNet, addForSubnet bool) *netlink.Rule {
	r := netlink.NewRule()
	r.Table = baseTableIndex + ifindex
	r.Priority = 10000
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

// AddSourceRule create a pbr rule for the address or subet which refers to the
// specific table for the ifindex.
func AddSourceRule(ifindex int, p net.IPNet, addForSubnet bool) {

	log.Infof("AddSourceRule(%d, %v, %v)", ifindex, p.String(), addForSubnet)
	r := makeNetlinkRule(ifindex, p, addForSubnet)
	log.Debugf("AddSourceRule: RuleAdd %v", r)
	// Avoid duplicate rules
	_ = netlink.RuleDel(r)
	if err := netlink.RuleAdd(r); err != nil {
		log.Errorf("RuleAdd %v failed with %s", r, err)
		return
	}
}

// DelSourceRule removes the pbr rule for the address or subet which refers to the
// specific table for the ifindex.
func DelSourceRule(ifindex int, p net.IPNet, addForSubnet bool) {

	log.Infof("DelSourceRule(%d, %v, %v)", ifindex, p.String(), addForSubnet)
	r := makeNetlinkRule(ifindex, p, addForSubnet)
	log.Debugf("DelSourceRule: RuleDel %v", r)
	if err := netlink.RuleDel(r); err != nil {
		log.Errorf("RuleDel %v failed with %s", r, err)
		return
	}
}
