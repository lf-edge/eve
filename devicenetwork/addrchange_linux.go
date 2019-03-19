// Copyright (c) 2017-2019 Zededa, Inc.
// All rights reserved.

// Look for address changes

// This file is built only for linux
// +build linux

package devicenetwork

import (
	"syscall"

	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
)

// Handle a link change
func LinkChange(change netlink.LinkUpdate) bool {

	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	changed := false
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		upFlag := RelevantAndUp(change.Link)
		log.Infof("LinkChange: NEWLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		changed = IfindexToNameAdd(ifindex, ifname, linkType, upFlag)
		log.Infof("LinkChange: changed %t index %d name %s type %s\n",
			changed, ifindex, ifname, linkType)
	case syscall.RTM_DELLINK:
		log.Infof("LinkChange: DELLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		changed = IfindexToNameDel(ifindex, ifname)
		log.Infof("LinkChange: changed %t index %d name %s type %s\n",
			changed, ifindex, ifname, linkType)
	}
	return changed
}
