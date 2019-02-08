// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free management ports.

// This file is built only for linux
// +build linux

package zedrouter

import (
	"syscall"

	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
)

// Return the first default route for one interface. XXX or return all?
func getDefaultIPv4Route(ifindex int) *netlink.Route {
	table := syscall.RT_TABLE_MAIN
	// Default route is nil Dst.
	filter := netlink.Route{Table: table, LinkIndex: ifindex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	log.Infof("getDefaultIPv4Route(%d) filter %v\n", ifindex, filter)
	routes, err := netlink.RouteListFiltered(syscall.AF_INET,
		&filter, fflags)
	if err != nil {
		log.Fatalf("RouteList failed: %v\n", err)
	}
	log.Debugf("getDefaultIPv4Route(%d) - got %d matches\n",
		ifindex, len(routes))
	for _, rt := range routes {
		if rt.LinkIndex != ifindex {
			continue
		}
		log.Debugf("getDefaultIPv4Route(%d) returning %v\n",
			ifindex, rt)
		return &rt
	}
	return nil
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
func PbrLinkChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.LinkUpdate) {

	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	log.Infof("PbrLinkChange: index %d name %s type %s\n", ifindex, ifname,
		linkType)
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		added := IfindexToNameAdd(ifindex, ifname, linkType)
		if added {
			if types.IsFreeMgmtPort(*deviceNetworkStatus,
				ifname) {

				log.Debugf("PbrLinkChange moving to FreeTable %s\n",
					ifname)
				moveRoutesTable(0, ifindex, FreeTable)
			}
			if types.IsMgmtPort(*deviceNetworkStatus, ifname) {
				log.Debugf("Link change for management port: %s\n",
					ifname)
				if addrChangeFuncMgmtPort != nil {
					addrChangeFuncMgmtPort(ifname)
				}
			} else {
				log.Debugf("Link change for non-port: %s\n",
					ifname)
				if addrChangeFuncNonMgmtPort != nil {
					addrChangeFuncNonMgmtPort(ifname)
				}
			}

		}
	case syscall.RTM_DELLINK:
		gone := IfindexToNameDel(ifindex, ifname)
		if gone {
			if types.IsFreeMgmtPort(*deviceNetworkStatus,
				ifname) {

				flushRoutesTable(FreeTable, ifindex)
			}
			MyTable := FreeTable + ifindex
			flushRoutesTable(MyTable, 0)
			flushRules(ifindex)
			if types.IsMgmtPort(*deviceNetworkStatus, ifname) {
				log.Debugf("Link change for management port: %s\n",
					ifname)
				if addrChangeFuncMgmtPort != nil {
					addrChangeFuncMgmtPort(ifname)
				}
			} else {
				log.Debugf("Link change for non-port: %s\n",
					ifname)
				if addrChangeFuncNonMgmtPort != nil {
					addrChangeFuncNonMgmtPort(ifname)
				}
			}

		}
	}
}
