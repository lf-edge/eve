// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Look for address changes

package devicenetwork

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
	"net"
	"reflect"
)

// Returns a channel for address updates
// Caller then does this in select loop:
//	case change := <-addrChanges:
//		changed := devicenetwork.AddrChange(&clientCtx, change)
//
func AddrChangeInit(log *base.LogObject) chan netlink.AddrUpdate {

	log.Functionf("AddrChangeInit()\n")

	addrchan := make(chan netlink.AddrUpdate)
	donechan := make(chan struct{})
	errFunc := func(err error) {
		log.Errorf("AddrSubscribe failed %s\n", err)
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
	log.Functionf("AddrChangeInit() DONE\n")
	return addrchan
}

// AddrChange handles an IP address change. Returns ifindex for changed interface
func AddrChange(ctx DeviceNetworkContext, change netlink.AddrUpdate) (bool, int) {

	log := ctx.Log
	changed := false
	if change.NewAddr {
		changed = IfindexToAddrsAdd(log, change.LinkIndex,
			change.LinkAddress.IP)
	} else {
		changed = IfindexToAddrsDel(log, change.LinkIndex,
			change.LinkAddress.IP)
	}
	if changed {
		ifname, _, err := IfindexToName(log, change.LinkIndex)
		if err != nil {
			log.Errorf("AddrChange IfindexToName failed for %d: %s\n",
				change.LinkIndex, err)
			return false, 0
		}
		isPort := types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname)
		if isPort {
			if change.NewAddr {
				AddSourceRule(log, change.LinkIndex, change.LinkAddress, false, PbrLocalOrigPrio)
			} else {
				DelSourceRule(log, change.LinkIndex, change.LinkAddress, false, PbrLocalOrigPrio)
			}
		}
		log.Functionf("AddrChange: changed, %d %s", change.LinkIndex, change.LinkAddress.String())
	} else {
		log.Tracef("AddrChange: no change, %d %s", change.LinkIndex, change.LinkAddress.String())
	}
	return changed, change.LinkIndex
}

// Returns a channel for link updates
// Caller then does this in select loop:
//	case change := <-linkChanges:
//		changed := devicenetwork.LinkChange(change)
//
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
//	case change := <-routeChanges:
//		PbrHandleRouteChange(..., change)
//
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

// Check if at least one management port in the given DeviceNetworkStatus
// have atleast one IP address each and at least one DNS server.
func checkIfMgmtPortsHaveIPandDNS(log *base.LogObject, status types.DeviceNetworkStatus) bool {

	mgmtPorts := types.GetMgmtPortsAny(status, 0)
	if len(mgmtPorts) == 0 {
		log.Functionf("XXX no management ports")
		return false
	}

	for _, port := range mgmtPorts {
		numAddrs, err := types.CountLocalIPv4AddrAnyNoLinkLocalIf(status, port)
		if err != nil {
			log.Errorf("CountLocalIPv4AddrAnyNoLinkLocalIf failed for %s: %v",
				port, err)
			continue
		}
		if numAddrs < 1 {
			log.Tracef("No addresses on %s", port)
			continue
		}
		numDNSServers := types.CountDNSServers(status, port)
		if numDNSServers < 1 {
			log.Tracef("Have addresses but no DNS on %s", port)
			continue
		}
		return true
	}
	return false
}

func HandleAddressChange(ctx *DeviceNetworkContext) {

	log := ctx.Log
	// Check if we have more or less addresses
	var dnStatus types.DeviceNetworkStatus

	log.Functionf("HandleAddressChange Pending.Inprogress %v",
		ctx.Pending.Inprogress)
	if !ctx.Pending.Inprogress {
		dnStatus = *ctx.DeviceNetworkStatus
		status := MakeDeviceNetworkStatus(ctx, *ctx.DevicePortConfig,
			dnStatus)

		if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, status) {
			log.Functionf("HandleAddressChange: change from %v to %v\n",
				*ctx.DeviceNetworkStatus, status)
			*ctx.DeviceNetworkStatus = status
			DoDNSUpdate(ctx)
		} else {
			log.Functionf("HandleAddressChange: No change\n")
		}
	} else {
		dnStatus = MakeDeviceNetworkStatus(ctx, *ctx.DevicePortConfig,
			ctx.Pending.PendDNS)

		if !reflect.DeepEqual(ctx.Pending.PendDNS, dnStatus) {
			log.Functionf("HandleAddressChange pending: change from %v to %v\n",
				ctx.Pending.PendDNS, dnStatus)
			pingTestDNS := checkIfMgmtPortsHaveIPandDNS(log, dnStatus)
			if pingTestDNS {
				// We have a suitable candiate for running our cloud ping test.
				log.Functionf("HandleAddressChange: Running cloud ping test now, " +
					"Since we have suitable addresses already.")
				VerifyDevicePortConfig(ctx)
			}
		} else {
			log.Functionf("HandleAddressChange pending: No change\n")
		}
	}
}

// RouteChange checks if a route change implies that an interface IP address might have changed.
// Returns ifindex for potentially changed interface
func RouteChange(ctx DeviceNetworkContext, change netlink.RouteUpdate) (bool, int) {

	log := ctx.Log
	rt := change.Route
	if rt.Table != getDefaultRouteTable() {
		// Ignore
		return false, 0
	}
	op := "NONE"
	if change.Type == getRouteUpdateTypeDELROUTE() {
		op = "DELROUTE"
	} else if change.Type == getRouteUpdateTypeNEWROUTE() {
		op = "NEWROUTE"
	}
	ifname, _, err := IfindexToName(log, rt.LinkIndex)
	if err != nil {
		log.Errorf("RouteChange IfindexToName failed for %d: %s\n",
			rt.LinkIndex, err)
		return false, 0
	}
	isPort := types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname)
	if !isPort {
		return false, 0
	}
	log.Functionf("RouteChange(%d/%s) %s %+v", rt.LinkIndex, ifname, op, rt)
	MyTable := baseTableIndex + rt.LinkIndex
	// Apply to ifindex specific table
	myrt := rt
	myrt.Table = MyTable
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	if myrt.Flags != 0 {
		myrt.Flags = 0
	}
	if change.Type == getRouteUpdateTypeDELROUTE() {
		log.Functionf("Received route del %v\n", rt)
		if err := netlink.RouteDel(&myrt); err != nil {
			log.Errorf("Failed to remove %v from %d: %s\n",
				myrt, myrt.Table, err)
		}
	} else if change.Type == getRouteUpdateTypeNEWROUTE() {
		log.Functionf("Received route add %v\n", rt)
		if err := netlink.RouteAdd(&myrt); err != nil {
			log.Errorf("Failed to add %v to %d: %s\n",
				myrt, myrt.Table, err)
		}
	}
	// Guess any onlink/attached route can imply an address change
	changed := (rt.Gw == nil)
	return changed, rt.LinkIndex
}

// Track changes to set of ports where we have applied PBR
var ifnameHasPBR = make(map[string][]net.IP)

// UpdatePBR makes sure we have PBR rules and routing tables for all the ports
// Track the list of old port addresses to detect if a port is added or deleted,
// or if the set of IP addresses change
func UpdatePBR(log *base.LogObject, status types.DeviceNetworkStatus) {

	log.Functionf("UpdatePBR: %d ports", len(status.Ports))
	// Track any ifnames which need to have PBR deleted
	ifnameFound := make(map[string]bool)

	for _, u := range status.Ports {
		ifnameFound[u.IfName] = true

		var addrs []net.IP
		for _, ai := range u.AddrInfoList {
			addrs = append(addrs, ai.Addr)
		}
		if oldAddrs, ok := ifnameHasPBR[u.IfName]; ok {
			if reflect.DeepEqual(oldAddrs, addrs) {
				log.Functionf("Ifname %s already has PBR",
					u.IfName)
				continue
			}
			log.Functionf("Ifname %s PBR changed from %v to %v",
				u.IfName, oldAddrs, addrs)
			delPBR(log, status, u.IfName)
			addPBR(log, status, u.IfName, addrs)
			ifnameHasPBR[u.IfName] = addrs
			continue
		}
		addPBR(log, status, u.IfName, addrs)
		ifnameHasPBR[u.IfName] = addrs
	}
	for old := range ifnameHasPBR {
		if _, ok := ifnameFound[old]; ok {
			continue
		}
		delPBR(log, status, old)
		delete(ifnameHasPBR, old)
	}
}

func addPBR(log *base.LogObject, status types.DeviceNetworkStatus, ifname string, addrs []net.IP) {
	log.Functionf("addPBR(%s) addrs %v", ifname, addrs)
	ifindex, err := IfnameToIndex(log, ifname)
	if err != nil {
		log.Errorf("addPBR can't find ifindex for %s", ifname)
		return
	}
	FlushRules(log, ifindex)
	for _, a := range addrs {
		AddSourceRule(log, ifindex, HostSubnet(a), false, PbrLocalOrigPrio)
	}
	// Flush then copy all routes for this interface to the table
	// for this ifindex
	table := baseTableIndex + ifindex
	FlushRoutesTable(log, table, 0)
	CopyRoutesTable(log, 0, ifindex, table)
}

func delPBR(log *base.LogObject, status types.DeviceNetworkStatus, ifname string) {
	log.Functionf("delPBR(%s)", ifname)
	ifindex, err := IfnameToIndex(log, ifname)
	if err != nil {
		log.Errorf("delPBR can't find ifindex for %s", ifname)
		return
	}
	FlushRules(log, ifindex)
	table := baseTableIndex + ifindex
	FlushRoutesTable(log, table, 0)
}
