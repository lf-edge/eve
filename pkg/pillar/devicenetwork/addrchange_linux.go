// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Look for address changes

// This file is built only for linux
// +build linux

package devicenetwork

import (
	"syscall"

	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
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
func LinkChange(change netlink.LinkUpdate) (bool, int) {

	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	changed := false
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		relevantFlag, upFlag := RelevantLastResort(change.Link)
		log.Infof("LinkChange: NEWLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		changed = IfindexToNameAdd(ifindex, ifname, linkType, relevantFlag, upFlag)
		log.Infof("LinkChange: changed %t index %d name %s type %s\n",
			changed, ifindex, ifname, linkType)
		if changed && relevantFlag && !upFlag {
			setLinkUp(ifname)
		}
	case syscall.RTM_DELLINK:
		log.Infof("LinkChange: DELLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		// Drop all cached addresses
		IfindexToAddrsFlush(ifindex)

		changed = IfindexToNameDel(ifindex, ifname)
		log.Infof("LinkChange: changed %t index %d name %s type %s\n",
			changed, ifindex, ifname, linkType)
	}
	return changed, ifindex
}

// Set up to be able to see LOWER-UP and NO-CARRIER in operStatus later
func setLinkUp(ifname string) {
	log.Infof("setLinkUp(%s)", ifname)
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
