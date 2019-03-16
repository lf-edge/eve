// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

// Look for address changes

package devicenetwork

import (
	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"reflect"
)

// Returns a channel for address updates
// Caller then does this in select loop:
//	case change := <-addrChanges:
//		devicenetwork.AddrChange(&clientCtx, change)
//
func AddrChangeInit(ctx *DeviceNetworkContext) chan netlink.AddrUpdate {

	log.Debugf("AddrChangeInit()\n")
	IfindexToNameInit()
	IfindexToAddrsInit()

	addrchan := make(chan netlink.AddrUpdate)
	errFunc := func(err error) {
		log.Errorf("AddrSubscribe failed %s\n", err)
	}
	addropt := netlink.AddrSubscribeOptions{
		ListExisting:      true,
		ErrorCallback:     errFunc,
		ReceiveBufferSize: 128 * 1024,
	}
	if err := netlink.AddrSubscribeWithOptions(addrchan, nil,
		addropt); err != nil {
		log.Fatal(err)
	}
	return addrchan
}

// Handle an IP address change
func AddrChange(ctx *DeviceNetworkContext, change netlink.AddrUpdate) {

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
	if changed {
		log.Infof("AddrChange changed %d %s\n",
			change.LinkIndex, change.LinkAddress.String())
		HandleAddressChange(ctx, "any")
	}
}

// Returns a channel for link updates
// Caller then does this in select loop:
//	case change := <-linkChanges:
//		devicenetwork.LinkChange(&clientCtx, change)
//
func LinkChangeInit(ctx *DeviceNetworkContext) chan netlink.LinkUpdate {

	log.Debugf("LinkChangeInit()\n")
	IfindexToNameInit()
	IfindexToAddrsInit()

	// Need links to get name to ifindex? Or lookup each time?
	linkchan := make(chan netlink.LinkUpdate)
	linkErrFunc := func(err error) {
		log.Errorf("LinkSubscribe failed %s\n", err)
	}
	linkopt := netlink.LinkSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: linkErrFunc,
	}
	if err := netlink.LinkSubscribeWithOptions(linkchan, nil,
		linkopt); err != nil {
		log.Fatal(err)
	}
	return linkchan
}

// Check if ports in the given DeviceNetworkStatus have atleast one
// IP address each.
func checkIfAllDNSPortsHaveIPAddrs(status types.DeviceNetworkStatus) bool {
	mgmtPorts := types.GetMgmtPortsFree(status, 0)
	if len(mgmtPorts) == 0 {
		return false
	}

	for _, port := range mgmtPorts {
		numAddrs := types.CountLocalAddrFreeNoLinkLocalIf(status, port)
		log.Debugf("checkIfAllDNSPortsHaveIPAddrs: Port %s has %d addresses.",
			port, numAddrs)
		if numAddrs < 1 {
			return false
		}
	}
	return true
}

// The ifname arg can only be used for logging
func HandleAddressChange(ctx *DeviceNetworkContext,
	ifname string) {

	// Check if we have more or less addresses
	var dnStatus types.DeviceNetworkStatus

	if !ctx.Pending.Inprogress {
		dnStatus = *ctx.DeviceNetworkStatus
		status, _ := MakeDeviceNetworkStatus(*ctx.DevicePortConfig,
			dnStatus)

		if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, status) {
			log.Debugf("HandleAddressChange: change for %s from %v to %v\n",
				ifname, *ctx.DeviceNetworkStatus, status)
			*ctx.DeviceNetworkStatus = status
			DoDNSUpdate(ctx)
		} else {
			log.Infof("HandleAddressChange: No change for %s\n", ifname)
		}
	} else {
		dnStatus = ctx.Pending.PendDNS
		dnStatus, _ = MakeDeviceNetworkStatus(*ctx.DevicePortConfig,
			dnStatus)

		pingTestDNS := checkIfAllDNSPortsHaveIPAddrs(dnStatus)
		if pingTestDNS {
			// We have a suitable candiate for running our cloud ping test.
			log.Infof("HandleAddressChange: Running cloud ping test now, " +
				"Since we have suitable addresses already.")
			VerifyDevicePortConfig(ctx)
		}
	}
}
