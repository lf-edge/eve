// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func delDummyInterface() {
	link, err := netlink.LinkByName("dnsmasq")
	if link == nil || err != nil {
		return
	}
	err = netlink.LinkDel(link)
	if err != nil {
		fmt.Println(err)
	}
}
func createDummyInterface(loAddr netlink.Addr) {
	dummy := netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: "dnsmasq"},
	}
	err := netlink.LinkAdd(&dummy)
	if err != nil {
		panic(err)
	}

	addrs, err := netlink.AddrList(&dummy, netlink.FAMILY_ALL)
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		err := netlink.AddrDel(&dummy, &addr)
		if err != nil {
			fmt.Println(err)
		}
	}

	err = netlink.AddrAdd(&dummy, &loAddr)
	if err != nil {
		panic(err)
	}

	err = netlink.LinkSetUp(&dummy)
	if err != nil {
		panic(err)
	}
}
