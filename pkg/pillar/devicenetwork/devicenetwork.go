// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"errors"
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

func IsProxyConfigEmpty(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) == 0 &&
		len(proxyConfig.ProxyCertPEM) == 0 &&
		proxyConfig.Exceptions == "" &&
		proxyConfig.Pacfile == "" &&
		proxyConfig.NetworkProxyEnable == false &&
		proxyConfig.NetworkProxyURL == "" {
		return true
	}
	return false
}

// GetIPAddrs return all IP addresses for an ifindex, and updates the cached info.
// Also returns the up flag (based on admin status), and hardware address.
// Leaves mask uninitialized
// It replaces what is in the Ifindex cache since AddrChange callbacks
// are far from reliable.
// If AddrChange worked reliably this would just be:
// return IfindexToAddrs(ifindex)
func GetIPAddrs(log *base.LogObject, ifindex int) ([]*net.IPNet, bool, net.HardwareAddr, error) {

	var addrs []*net.IPNet
	var up bool
	var macAddr net.HardwareAddr

	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		err = errors.New(fmt.Sprintf("Port in config/global does not exist: %d",
			ifindex))
		return addrs, up, macAddr, err
	}
	addrs4, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.Warnf("netlink.AddrList %d V4 failed: %s", ifindex, err)
		addrs4 = nil
	}
	addrs6, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		log.Warnf("netlink.AddrList %d V4 failed: %s", ifindex, err)
		addrs6 = nil
	}
	attrs := link.Attrs()
	up = (attrs.Flags & net.FlagUp) != 0
	if attrs.HardwareAddr != nil {
		macAddr = attrs.HardwareAddr
	}

	log.Functionf("GetIPAddrs(%d) found %v and %v", ifindex, addrs4, addrs6)
	IfindexToAddrsFlush(log, ifindex)
	for _, a := range addrs4 {
		if a.IP == nil {
			continue
		}
		addrs = append(addrs, a.IPNet)
		IfindexToAddrsAdd(log, ifindex, a.IPNet)
	}
	for _, a := range addrs6 {
		if a.IP == nil {
			continue
		}
		addrs = append(addrs, a.IPNet)
		IfindexToAddrsAdd(log, ifindex, a.IPNet)
	}
	return addrs, up, macAddr, nil

}
