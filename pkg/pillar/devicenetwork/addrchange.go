// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Look for address changes

package devicenetwork

import (
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"reflect"
)

// Returns a channel for address updates
// Caller then does this in select loop:
//	case change := <-addrChanges:
//		changed := devicenetwork.AddrChange(&clientCtx, change)
//
func AddrChangeInit() chan netlink.AddrUpdate {

	log.Debugf("AddrChangeInit()\n")

	addrchan := make(chan netlink.AddrUpdate)
	donechan := make(chan struct{})
	errFunc := func(err error) {
		log.Errorf("AddrSubscribe failed %s\n", err)
		donechan <- struct{}{}
	}
	addropt := netlink.AddrSubscribeOptions{
		ListExisting:      true,
		ErrorCallback:     errFunc,
		ReceiveBufferSize: 128 * 1024,
	}
	if err := netlink.AddrSubscribeWithOptions(addrchan, donechan,
		addropt); err != nil {
		log.Fatal(err)
	}
	return addrchan
}

// Handle an IP address change. Returns changed bool
func AddrChange(change netlink.AddrUpdate) bool {

	changed := false
	if change.NewAddr {
		log.Infof("AddrChange new %d %s\n",
			change.LinkIndex, change.LinkAddress.String())
		changed = IfindexToAddrsAdd(change.LinkIndex,
			change.LinkAddress)
	} else {
		log.Infof("AddrChange del %d %s\n",
			change.LinkIndex, change.LinkAddress.String())
		changed = IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress)
	}
	return changed
}

// Returns a channel for link updates
// Caller then does this in select loop:
//	case change := <-linkChanges:
//		changed := devicenetwork.LinkChange(change)
//
func LinkChangeInit() chan netlink.LinkUpdate {

	log.Debugf("LinkChangeInit()\n")

	// Need links to get name to ifindex? Or lookup each time?
	linkchan := make(chan netlink.LinkUpdate)
	donechan := make(chan struct{})
	linkErrFunc := func(err error) {
		log.Errorf("LinkSubscribe failed %s\n", err)
		donechan <- struct{}{}
	}
	linkopt := netlink.LinkSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: linkErrFunc,
	}
	if err := netlink.LinkSubscribeWithOptions(linkchan, donechan,
		linkopt); err != nil {
		log.Fatal(err)
	}
	return linkchan
}

// Returns a channel for route updates
// Caller then does this in select loop:
//	case change := <-routeChanges:
//		PbrHandleRouteChange(..., change)
//
func RouteChangeInit() chan netlink.RouteUpdate {

	log.Debugf("RouteChangeInit()\n")

	routechan := make(chan netlink.RouteUpdate)
	donechan := make(chan struct{})
	routeErrFunc := func(err error) {
		log.Errorf("RouteSubscribe failed %s\n", err)
		donechan <- struct{}{}
	}
	rtopt := netlink.RouteSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: routeErrFunc,
	}
	if err := netlink.RouteSubscribeWithOptions(routechan, donechan,
		rtopt); err != nil {
		log.Fatal(err)
	}
	return routechan
}

// Check if ports in the given DeviceNetworkStatus have atleast one
// IP address each.
func checkIfAllDNSPortsHaveIPAddrs(status types.DeviceNetworkStatus) bool {
	mgmtPorts := types.GetMgmtPortsFree(status, 0)
	if len(mgmtPorts) == 0 {
		return false
	}

	for _, port := range mgmtPorts {
		numAddrs := types.CountLocalIPv4AddrAnyNoLinkLocalIf(status, port)
		log.Debugf("checkIfAllDNSPortsHaveIPAddrs: Port %s has %d addresses.",
			port, numAddrs)
		if numAddrs < 1 {
			return false
		}
	}
	return true
}

func HandleAddressChange(ctx *DeviceNetworkContext) {

	// Check if we have more or less addresses
	var dnStatus types.DeviceNetworkStatus

	log.Infof("HandleAddressChange Pending.Inprogress %v",
		ctx.Pending.Inprogress)
	if !ctx.Pending.Inprogress {
		dnStatus = *ctx.DeviceNetworkStatus
		status, _ := MakeDeviceNetworkStatus(*ctx.DevicePortConfig,
			dnStatus)

		if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, status) {
			log.Debugf("HandleAddressChange: change from %v to %v\n",
				*ctx.DeviceNetworkStatus, status)
			*ctx.DeviceNetworkStatus = status
			DoDNSUpdate(ctx)
		} else {
			log.Infof("HandleAddressChange: No change\n")
		}
	} else {
		dnStatus = ctx.Pending.PendDNS
		dnStatus, _ = MakeDeviceNetworkStatus(*ctx.DevicePortConfig,
			dnStatus)

		if !reflect.DeepEqual(ctx.Pending.PendDNS, dnStatus) {
			log.Debugf("HandleAddressChange pending: change from %v to %v\n",
				ctx.Pending.PendDNS, dnStatus)
			pingTestDNS := checkIfAllDNSPortsHaveIPAddrs(dnStatus)
			if pingTestDNS {
				// We have a suitable candiate for running our cloud ping test.
				log.Infof("HandleAddressChange: Running cloud ping test now, " +
					"Since we have suitable addresses already.")
				VerifyDevicePortConfig(ctx)
			}
		} else {
			log.Infof("HandleAddressChange pending: No change\n")
		}
	}
}
