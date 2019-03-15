// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

// Look for address changes

package devicenetwork

import (
	"errors"
	"fmt"
	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"net"
	"reflect"
	"syscall"
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
		changed = IfindexToAddrsAdd(ctx, change.LinkIndex,
			change.LinkAddress)
	} else {
		log.Infof("AddrChange del %d %s\n",
			change.LinkIndex, change.LinkAddress.String())
		changed = IfindexToAddrsDel(ctx, change.LinkIndex,
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

// XXX move to _linux.go file
// Handle a link change
func LinkChange(ctx *DeviceNetworkContext, change netlink.LinkUpdate) {

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

// ===== map from ifindex to ifname

type linkNameType struct {
	linkName string
	linkType string
}

// XXX - IfIndexToName mapping is used outside of PBR as well. Better
//	to move it into a separate module.
var ifindexToName map[int]linkNameType

func IfindexToNameInit() {
	ifindexToName = make(map[int]linkNameType)
}

// Returns true if added
func IfindexToNameAdd(index int, linkName string, linkType string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		// Note that we get RTM_NEWLINK even for link changes
		// hence we don't print unless the entry is new
		log.Infof("IfindexToNameAdd index %d name %s type %s\n",
			index, linkName, linkType)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else if m.linkName != linkName {
		// We get this when the vifs are created with "vif*" names
		// and then changed to "bu*" etc.
		log.Infof("IfindexToNameAdd name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return false
	} else {
		return false
	}
}

// Returns true if deleted
func IfindexToNameDel(index int, linkName string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		log.Errorf("IfindexToNameDel unknown index %d\n", index)
		return false
	} else if m.linkName != linkName {
		log.Errorf("IfindexToNameDel name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		delete(ifindexToName, index)
		// log.Debugf("ifindexToName post delete %v\n", ifindexToName)
		return true
	} else {
		log.Debugf("IfindexToNameDel index %d name %s\n",
			index, linkName)
		delete(ifindexToName, index)
		// log.Debugf("ifindexToName post delete %v\n", ifindexToName)
		return true
	}
}

// Returns linkName, linkType
func IfindexToName(index int) (string, string, error) {
	n, ok := ifindexToName[index]
	if ok {
		return n.linkName, n.linkType, nil
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	linkName := link.Attrs().Name
	linkType := link.Type()
	log.Warnf("IfindexToName(%d) fallback lookup done: %s, %s\n",
		index, linkName, linkType)
	IfindexToNameAdd(index, linkName, linkType)
	return linkName, linkType, nil
}

func IfnameToIndex(ifname string) (int, error) {
	for i, lnt := range ifindexToName {
		if lnt.linkName == ifname {
			return i, nil
		}
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Unknown ifname %s", ifname))
	}
	index := link.Attrs().Index
	linkType := link.Type()
	log.Warnf("IfnameToIndex(%s) fallback lookup done: %d, %s\n",
		ifname, index, linkType)
	IfindexToNameAdd(index, ifname, linkType)
	return index, nil
}

// ===== map from ifindex to list of IP addresses

var ifindexToAddrs map[int][]net.IPNet

func IfindexToAddrsInit() {
	ifindexToAddrs = make(map[int][]net.IPNet)
}

// Returns true if added
func IfindexToAddrsAdd(ctx *DeviceNetworkContext, index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
		return true
	}
	found := false
	for _, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			found = true
			break
		}
	}
	if !found {
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
	}
	return !found
}

// Returns true if deleted
func IfindexToAddrsDel(ctx *DeviceNetworkContext, index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Warnf("IfindexToAddrsDel unknown index %d\n", index)
		return false
	}
	for i, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			log.Debugf("IfindexToAddrsDel del %v for %d\n",
				addr, index)
			ifindexToAddrs[index] = append(ifindexToAddrs[index][:i],
				ifindexToAddrs[index][i+1:]...)
			// log.Debugf("ifindexToAddrs post remove %v\n", ifindexToAddrs)
			// XXX should we check for zero and remove ifindex?
			return true
		}
	}
	log.Warnf("IfindexToAddrsDel address not found for %d in %v\n",
		index, addrs)
	return false
}

func IfindexToAddrs(index int) ([]net.IPNet, error) {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	return addrs, nil
}
