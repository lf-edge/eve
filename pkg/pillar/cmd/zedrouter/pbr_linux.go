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

// Used when FreeMgmtPorts get a link added
// If ifindex is non-zero we also compare it
func moveRoutesTable(srcTable int, ifindex int, dstTable int) {
	if srcTable == 0 {
		srcTable = getDefaultRouteTable()
	}
	filter := netlink.Route{Table: srcTable, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	if ifindex != 0 {
		fflags |= netlink.RT_FILTER_OIF
	}
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatalf("RouteList failed: %v\n", err)
	}
	log.Debugf("moveRoutesTable(%d, %d, %d) - got %d\n",
		srcTable, ifindex, dstTable, len(routes))
	for _, rt := range routes {
		if rt.Table != srcTable {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		art := rt
		art.Table = dstTable
		// Multiple IPv6 link-locals can't be added to the same
		// table unless the Priority differs. Different
		// LinkIndex, Src, Scope doesn't matter.
		if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
			log.Debugf("Forcing IPv6 priority to %v\n",
				rt.LinkIndex)
			// Hack to make the kernel routes not appear identical
			art.Priority = rt.LinkIndex
		}
		// Clear any RTNH_F_LINKDOWN etc flags since add doesn't
		// like them
		if rt.Flags != 0 {
			art.Flags = 0
		}
		log.Debugf("moveRoutesTable(%d, %d, %d) adding %v\n",
			srcTable, ifindex, dstTable, art)
		if err := netlink.RouteAdd(&art); err != nil {
			log.Errorf("moveRoutesTable failed to add %v to %d: %s\n",
				art, art.Table, err)
		}
	}
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
			if types.IsFreeMgmtPort(*deviceNetworkStatus,
				ifname) {

				log.Debugf("PbrLinkChange moving to FreeTable %s\n",
					ifname)
				moveRoutesTable(0, ifindex, FreeTable)
			}
		}
	case syscall.RTM_DELLINK:
		gone := devicenetwork.IfindexToNameDel(ifindex, ifname)
		if gone {
			changed = true
			if types.IsFreeMgmtPort(*deviceNetworkStatus,
				ifname) {

				flushRoutesTable(FreeTable, ifindex)
			}
			MyTable := FreeTable + ifindex
			flushRoutesTable(MyTable, 0)
			flushRules(ifindex)
		}
	}
	if changed {
		return ifname
	}
	return ""
}
