// Copyright (c) 2017,2018 Zededa, Inc.
// All rights reserved.

// Look for address changes

package devicenetwork

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"reflect"
)

// Returns a channel for address updates
// Caller then does this in select loop:
//	case change := <-addrChanges:
//		devicenetwork.AddrChange(&clientCtx, change)
//
func AddrChangeInit(ctx *DeviceNetworkContext) chan netlink.AddrUpdate {
	if debug {
		log.Printf("AddrChangeInit()\n")
	}
	IfindexToAddrsInit()

	addrchan := make(chan netlink.AddrUpdate)
	addropt := netlink.AddrSubscribeOptions{ListExisting: true}
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
		changed = IfindexToAddrsAdd(change.LinkIndex,
			change.LinkAddress)
	} else {
		changed = IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress)
	}
	if changed {
		// Check if we have more or less addresses
		status, _ := MakeDeviceNetworkStatus(*ctx.DeviceUplinkConfig,
			*ctx.DeviceNetworkStatus)
		if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, status) {
			if debug {
				log.Printf("Address change from %v to %v\n",
					*ctx.DeviceNetworkStatus,
					status)
			}
			*ctx.DeviceNetworkStatus = status
			DoDNSUpdate(ctx)
		}
	}
}

// ===== map from ifindex to list of IP addresses

var ifindexToAddrs map[int][]net.IPNet

func IfindexToAddrsInit() {
	ifindexToAddrs = make(map[int][]net.IPNet)
}

// Returns true if added
func IfindexToAddrsAdd(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		if debug {
			log.Printf("IfindexToAddrsAdd add %v for %d\n",
				addr, index)
		}
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Printf("ifindexToAddrs post add %v\n", ifindexToAddrs)
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
		if debug {
			log.Printf("IfindexToAddrsAdd add %v for %d\n",
				addr, index)
		}
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Printf("ifindexToAddrs post add %v\n", ifindexToAddrs)
	}
	return !found
}

// Returns true if deleted
func IfindexToAddrsDel(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Printf("IfindexToAddrsDel unknown index %d\n", index)
		// XXX error?
		return false
	}
	for i, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			if debug {
				log.Printf("IfindexToAddrsDel del %v for %d\n",
					addr, index)
			}
			ifindexToAddrs[index] = append(ifindexToAddrs[index][:i],
				ifindexToAddrs[index][i+1:]...)
			// log.Printf("ifindexToAddrs post remove %v\n", ifindexToAddrs)
			// XXX should we check for zero and remove ifindex?
			return true
		}
	}
	log.Printf("IfindexToAddrsDel address not found for %d in\n",
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
