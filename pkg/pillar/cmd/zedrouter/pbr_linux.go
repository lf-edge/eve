// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free management ports.

// This file is built only for linux
//go:build linux
// +build linux

package zedrouter

import (
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// Return the all routes for one interface
func getAllIPv4Routes(ifindex int) []netlink.Route {
	table := syscall.RT_TABLE_MAIN
	filter := netlink.Route{Table: table, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	log.Functionf("getAllIPv4Routes(%d) filter %v\n", ifindex, filter)
	routes, err := netlink.RouteListFiltered(syscall.AF_INET,
		&filter, fflags)
	if err != nil {
		log.Errorf("getAllIPv4Routes: ifindex %d failed, error %v", ifindex, err)
		return nil
	}
	log.Tracef("getAllIPv4Routes(%d) - got %d matches\n",
		ifindex, len(routes))
	return routes
}

func getDefaultRouteTable() int {
	return syscall.RT_TABLE_MAIN
}

func getRouteUpdateTypeDELROUTE() uint16 {
	return syscall.RTM_DELROUTE
}

func getRouteUpdateTypeNEWROUTE() uint16 {
	return syscall.RTM_NEWROUTE
}

// Handle a link being added or deleted
// Returns the ifname if there was a change
func PbrLinkChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.LinkUpdate) string {

	changed := false
	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	log.Functionf("PbrLinkChange: index %d name %s type %s\n", ifindex, ifname,
		linkType)
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		// Must check current ifindex to since NEWLINK message could be older
		// than current kernel state and we have renames between ethN and kethN
		// which look like apparent ifindex changes to ethN
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			log.Errorf("PbrLinkChange: Unknown kernel ifname %s: %v", ifname, err)
			return ""
		}
		index := link.Attrs().Index
		if index != ifindex {
			log.Noticef("PbrLinkChange: different ifindex %d vs reported %d for %s",
				index, ifindex, ifname)
			ifindex = index
		}
		added := IfindexToNameAdd(log, ifindex, ifname, linkType)
		if added {
			changed = true
		}
	case syscall.RTM_DELLINK:
		gone := IfindexToNameDel(log, ifindex, ifname)
		if gone {
			changed = true
			MyTable := baseTableIndex + ifindex
			devicenetwork.FlushRoutesTable(log, MyTable, 0)
			devicenetwork.FlushRules(log, ifindex)
		}
	}
	if changed {
		return ifname
	}
	return ""
}
