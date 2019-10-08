// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free management ports.

// This file is built only for linux
// +build linux

package devicenetwork

import (
	"syscall"

	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
)

// CopyRoutesTable adds routes from one table to another.
// If ifindex is non-zero we also compare it
func CopyRoutesTable(srcTable int, ifindex int, dstTable int) {
	if srcTable == 0 {
		srcTable = getDefaultRouteTable()
	}
	filter := netlink.Route{Table: srcTable, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	if ifindex != 0 {
		fflags |= netlink.RT_FILTER_OIF
	}
	// XXX is AF_UNSPEC ok?
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatalf("RouteList failed: %v", err)
	}
	log.Infof("CopyRoutesTable(%d, %d, %d) - got %d",
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
			log.Debugf("Forcing IPv6 priority to %v",
				rt.LinkIndex)
			// Hack to make the kernel routes not appear identical
			art.Priority = rt.LinkIndex
		}
		// Clear any RTNH_F_LINKDOWN etc flags since add doesn't
		// like them
		if rt.Flags != 0 {
			art.Flags = 0
		}
		log.Infof("CopyRoutesTable(%d, %d, %d) adding %v",
			srcTable, ifindex, dstTable, art)
		if err := netlink.RouteAdd(&art); err != nil {
			log.Errorf("CopyRoutesTable failed to add %v to %d: %s",
				art, art.Table, err)
		}
	}
}
