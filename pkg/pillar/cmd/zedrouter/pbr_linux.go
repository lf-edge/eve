// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free management ports.

// This file is built only for linux
// +build linux

package zedrouter

import (
	"syscall"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Return the all routes for one interface
func getAllIPv4Routes(ifindex int) []netlink.Route {
	table := syscall.RT_TABLE_MAIN
	filter := netlink.Route{Table: table, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	log.Infof("getAllIPv4Routes(%d) filter %v\n", ifindex, filter)
	routes, err := netlink.RouteListFiltered(syscall.AF_INET,
		&filter, fflags)
	if err != nil {
		log.Fatalf("RouteList failed: %v\n", err)
	}
	log.Debugf("getAllIPv4Routes(%d) - got %d matches\n",
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
	log.Infof("PbrLinkChange: index %d name %s type %s\n", ifindex, ifname,
		linkType)
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		relevantFlag, upFlag := devicenetwork.RelevantLastResort(change.Link)
		added := devicenetwork.IfindexToNameAdd(ifindex, ifname, linkType,
			relevantFlag, upFlag)
		if added {
			changed = true
		}
	case syscall.RTM_DELLINK:
		gone := devicenetwork.IfindexToNameDel(ifindex, ifname)
		if gone {
			changed = true
			MyTable := baseTableIndex + ifindex
			devicenetwork.FlushRoutesTable(MyTable, 0)
			devicenetwork.FlushRules(ifindex)
		}
	}
	if changed {
		return ifname
	}
	return ""
}
