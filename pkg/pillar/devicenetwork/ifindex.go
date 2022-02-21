// Copyright (c) 2017-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Track ifindex to name plus IP addresses

package devicenetwork

import (
	"bytes"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// ===== map from ifindex to list of IP addresses

var ifindexToAddrs = make(map[int][]*net.IPNet)

// IfindexToAddrsAdd adds an IP address to the map for the ifindex
// if it doesn't already exist
// Returns true if added
func IfindexToAddrsAdd(log *base.LogObject, index int, addr *net.IPNet) bool {
	log.Tracef("IfindexToAddrsAdd(%d, %s)", index, addr.String())
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Tracef("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Tracef("ifindexToAddrs post add %v\n", ifindexToAddrs)
		return true
	}
	found := false
	for _, a := range addrs {
		if a.IP.Equal(addr.IP) && bytes.Compare(a.Mask, addr.Mask) == 0 {
			found = true
			break
		}
	}
	if !found {
		log.Tracef("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Tracef("ifindexToAddrs post add %v\n", ifindexToAddrs)
	}
	return !found
}

// IfindexToAddrsFlush removes all addresses for the ifindex
func IfindexToAddrsFlush(log *base.LogObject, index int) {
	_, ok := ifindexToAddrs[index]
	if !ok {
		log.Warnf("IfindexToAddrsFlush: Unknown ifindex %d", index)
		return
	}
	log.Functionf("IfindexToAddrsFlush(%d) removing %v",
		index, ifindexToAddrs[index])
	var addrs []*net.IPNet
	ifindexToAddrs[index] = addrs
}
