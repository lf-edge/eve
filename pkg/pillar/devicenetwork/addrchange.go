// Copyright (c) 2017,2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Look for address changes

package devicenetwork

import (
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"net"
	"reflect"
)

// Returns a channel for address updates
// Caller then does this in select loop:
//	case change := <-addrChanges:
//		changed := devicenetwork.AddrChange(&clientCtx, change)
//
func AddrChangeInit() chan netlink.AddrUpdate {

	log.Infof("AddrChangeInit()\n")

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
	log.Infof("AddrChangeInit() DONE\n")
	return addrchan
}

// AddrChange handles an IP address change. Returns ifindex for changed interface
func AddrChange(ctx DeviceNetworkContext, change netlink.AddrUpdate) (bool, int) {

	changed := false
	if change.NewAddr {
		log.Infof("AddrChange new %d %s\n",
			change.LinkIndex, change.LinkAddress.String())
		changed = IfindexToAddrsAdd(change.LinkIndex,
			change.LinkAddress.IP)
	} else {
		log.Infof("AddrChange del %d %s\n",
			change.LinkIndex, change.LinkAddress.String())
		changed = IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress.IP)
	}
	if changed {
		ifname, _, err := IfindexToName(change.LinkIndex)
		if err != nil {
			log.Errorf("AddrChange IfindexToName failed for %d: %s\n",
				change.LinkIndex, err)
			return false, 0
		}
		isPort := types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname)
		if isPort {
			if change.NewAddr {
				AddSourceRule(change.LinkIndex, change.LinkAddress, false)
			} else {
				DelSourceRule(change.LinkIndex, change.LinkAddress, false)
			}
		}
	}
	log.Infof("AddrChange %t %d %s", changed,
		change.LinkIndex, change.LinkAddress.String())
	return changed, change.LinkIndex
}

// Returns a channel for link updates
// Caller then does this in select loop:
//	case change := <-linkChanges:
//		changed := devicenetwork.LinkChange(change)
//
func LinkChangeInit() chan netlink.LinkUpdate {

	log.Infof("LinkChangeInit()\n")

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
	log.Infof("LinkChangeInit() DONE\n")
	return linkchan
}

// Returns a channel for route updates
// Caller then does this in select loop:
//	case change := <-routeChanges:
//		PbrHandleRouteChange(..., change)
//
func RouteChangeInit() chan netlink.RouteUpdate {

	log.Infof("RouteChangeInit()\n")

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
	log.Infof("RouteChangeInit() DONE\n")
	return routechan
}

// Check if ports in the given DeviceNetworkStatus have atleast one
// IP address each and at least one DNS server.
func checkIfAllPortsHaveIPandDNS(status types.DeviceNetworkStatus) bool {
	log.Infof("XXX checkIfAllPortsHaveIPandDNS")
	mgmtPorts := types.GetMgmtPortsAny(status, 0)
	if len(mgmtPorts) == 0 {
		log.Infof("XXX no management ports")
		return false
	}

	for _, port := range mgmtPorts {
		numAddrs := types.CountLocalIPv4AddrAnyNoLinkLocalIf(status, port)
		if numAddrs < 1 {
			log.Infof("XXX No addresses on %s", port)
			log.Debugf("No addresses on %s", port)
			return false
		}
		numDNSServers := types.CountDNSServers(status, port)
		if numDNSServers < 1 {
			log.Infof("XXX Have addresses but no DNS on %s", port)
			log.Debugf("Have addresses but no DNS on %s", port)
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
			log.Infof("HandleAddressChange: change from %v to %v\n",
				*ctx.DeviceNetworkStatus, status)
			*ctx.DeviceNetworkStatus = status
			DoDNSUpdate(ctx)
		} else {
			log.Infof("HandleAddressChange: No change\n")
		}
	} else {
		dnStatus, _ = MakeDeviceNetworkStatus(*ctx.DevicePortConfig,
			ctx.Pending.PendDNS)

		if !reflect.DeepEqual(ctx.Pending.PendDNS, dnStatus) {
			log.Infof("HandleAddressChange pending: change from %v to %v\n",
				ctx.Pending.PendDNS, dnStatus)
			pingTestDNS := checkIfAllPortsHaveIPandDNS(dnStatus)
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

// RouteChange checks if a route change implies that an interface IP address might have changed.
// Returns ifindex for potentially changed interface
func RouteChange(ctx DeviceNetworkContext, change netlink.RouteUpdate) (bool, int) {

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
	ifname, _, err := IfindexToName(rt.LinkIndex)
	if err != nil {
		log.Errorf("RouteChange IfindexToName failed for %d: %s\n",
			rt.LinkIndex, err)
		return false, 0
	}
	isPort := types.IsMgmtPort(*ctx.DeviceNetworkStatus, ifname)
	if !isPort {
		return false, 0
	}
	log.Infof("RouteChange(%d/%s) %s %+v", rt.LinkIndex, ifname, op, rt)
	MyTable := baseTableIndex + rt.LinkIndex
	// Apply to ifindex specific table
	myrt := rt
	myrt.Table = MyTable
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	if myrt.Flags != 0 {
		myrt.Flags = 0
	}
	if change.Type == getRouteUpdateTypeDELROUTE() {
		log.Infof("Received route del %v\n", rt)
		if err := netlink.RouteDel(&myrt); err != nil {
			log.Errorf("Failed to remove %v from %d: %s\n",
				myrt, myrt.Table, err)
		}
	} else if change.Type == getRouteUpdateTypeNEWROUTE() {
		log.Infof("Received route add %v\n", rt)
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
func UpdatePBR(status types.DeviceNetworkStatus) {

	log.Infof("UpdatePBR: %d ports", len(status.Ports))
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
				log.Infof("Ifname %s already has PBR",
					u.IfName)
				continue
			}
			log.Infof("Ifname %s PBR changed from %v to %v",
				u.IfName, oldAddrs, addrs)
			delPBR(status, u.IfName)
			addPBR(status, u.IfName, addrs)
			ifnameHasPBR[u.IfName] = addrs
			continue
		}
		addPBR(status, u.IfName, addrs)
		ifnameHasPBR[u.IfName] = addrs
	}
	for old := range ifnameHasPBR {
		if _, ok := ifnameFound[old]; ok {
			continue
		}
		delPBR(status, old)
		delete(ifnameHasPBR, old)
	}
}

func addPBR(status types.DeviceNetworkStatus, ifname string, addrs []net.IP) {
	log.Infof("addPBR(%s) addrs %v", ifname, addrs)
	ifindex, err := IfnameToIndex(ifname)
	if err != nil {
		log.Errorf("addPBR can't find ifindex for %s", ifname)
		return
	}
	FlushRules(ifindex)
	for _, a := range addrs {
		var subnet net.IPNet
		if a.To4() != nil {
			subnet = net.IPNet{IP: a, Mask: net.CIDRMask(32, 32)}
		} else {
			subnet = net.IPNet{IP: a, Mask: net.CIDRMask(128, 128)}
		}
		AddSourceRule(ifindex, subnet, false)
	}
	// Flush then copy all routes for this interface to the table
	// for this ifindex
	table := baseTableIndex + ifindex
	FlushRoutesTable(table, 0)
	CopyRoutesTable(0, ifindex, table)
}

func delPBR(status types.DeviceNetworkStatus, ifname string) {
	log.Infof("delPBR(%s)", ifname)
	ifindex, err := IfnameToIndex(ifname)
	if err != nil {
		log.Errorf("delPBR can't find ifindex for %s", ifname)
		return
	}
	FlushRules(ifindex)
	table := baseTableIndex + ifindex
	FlushRoutesTable(table, 0)
}
