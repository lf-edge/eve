// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Look for address changes

package devicenetwork

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

// Returns a channel for link updates
// Caller then does this in select loop:
//
//	case change := <-linkChanges:
//		changed := devicenetwork.LinkChange(change)
func LinkChangeInit(log *base.LogObject) chan netlink.LinkUpdate {

	log.Functionf("LinkChangeInit()\n")

	// Need links to get name to ifindex? Or lookup each time?
	linkchan := make(chan netlink.LinkUpdate)
	donechan := make(chan struct{})
	linkErrFunc := func(err error) {
		log.Errorf("LinkSubscribe failed %s\n", err)
	}
	linkopt := netlink.LinkSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: linkErrFunc,
	}
	if err := netlink.LinkSubscribeWithOptions(linkchan, donechan,
		linkopt); err != nil {
		log.Fatal(err)
	}
	log.Functionf("LinkChangeInit() DONE\n")
	return linkchan
}

// Returns a channel for route updates
// Caller then does this in select loop:
//
//	case change := <-routeChanges:
//		PbrHandleRouteChange(..., change)
func RouteChangeInit(log *base.LogObject) chan netlink.RouteUpdate {

	log.Functionf("RouteChangeInit()\n")

	routechan := make(chan netlink.RouteUpdate)
	donechan := make(chan struct{})
	routeErrFunc := func(err error) {
		log.Errorf("RouteSubscribe failed %s\n", err)
	}
	rtopt := netlink.RouteSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: routeErrFunc,
	}
	if err := netlink.RouteSubscribeWithOptions(routechan, donechan,
		rtopt); err != nil {
		log.Fatal(err)
	}
	log.Functionf("RouteChangeInit() DONE\n")
	return routechan
}
