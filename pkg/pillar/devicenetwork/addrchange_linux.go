// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Look for address changes

// This file is built only for linux
// +build linux

package devicenetwork

import (
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

func getDefaultRouteTable() int {
	return syscall.RT_TABLE_MAIN
}

func getRouteUpdateTypeDELROUTE() uint16 {
	return syscall.RTM_DELROUTE
}

func getRouteUpdateTypeNEWROUTE() uint16 {
	return syscall.RTM_NEWROUTE
}

// LinkChange handles a link change. Returns ifindex for changed interface
func LinkChange(log *base.LogObject, change netlink.LinkUpdate) (bool, int) {

	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	changed := false
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		relevantFlag, upFlag := RelevantLastResort(log, change.Link)
		log.Functionf("LinkChange: NEWLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		// Must check current ifindex to since NEWLINK message could be older
		// than current kernel state and we have renames between ethN and kethN
		// which look like apparent ifindex changes to ethN
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			log.Errorf("LinkChange: Unknown kernel ifname %s: %v", ifname, err)
			return changed, -1
		}
		index := link.Attrs().Index
		if index != ifindex {
			log.Noticef("LinkChange: different ifindex %d vs reported %d for %s",
				index, ifindex, ifname)
			ifindex = index
		}
		changed = IfindexToNameAdd(log, ifindex, ifname, linkType, relevantFlag, upFlag)
		log.Functionf("LinkChange: changed %t index %d name %s type %s\n",
			changed, ifindex, ifname, linkType)
		if changed && relevantFlag && !upFlag {
			setLinkUp(log, ifname)
		}
	case syscall.RTM_DELLINK:
		log.Functionf("LinkChange: DELLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		// Drop all cached addresses
		IfindexToAddrsFlush(log, ifindex)

		changed = IfindexToNameDel(log, ifindex, ifname)
		log.Functionf("LinkChange: changed %t index %d name %s type %s\n",
			changed, ifindex, ifname, linkType)
	}
	return changed, ifindex
}

// Set up to be able to see LOWER-UP and NO-CARRIER in operStatus later
func setLinkUp(log *base.LogObject, ifname string) {
	log.Functionf("setLinkUp(%s)", ifname)
	link, err := netlink.LinkByName(ifname)
	if link == nil {
		log.Warnf("Can't find link %s: %s\n", ifname, err)
		return
	}
	//    ip link set ${ifname} up
	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("LinkSetUp on %s failed: %s", ifname, err)
		return
	}
}
