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
func LinkChange(change netlink.LinkUpdate) {

	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		log.Infof("LinkChange: NEWLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		added := IfindexToNameAdd(ifindex, ifname, linkType)
		log.Infof("LinkChange: added %t index %d name %s type %s\n",
			added, ifindex, ifname, linkType)
	case syscall.RTM_DELLINK:
		log.Infof("LinkChange: DELLINK index %d name %s type %s\n",
			ifindex, ifname, linkType)
		gone := IfindexToNameDel(ifindex, ifname)
		log.Infof("LinkChange: deleted %t index %d name %s type %s\n",
			gone, ifindex, ifname, linkType)
	}
}
