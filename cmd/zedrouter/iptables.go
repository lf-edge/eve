// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// iptables support code

package main

import (
	"github.com/zededa/go-provision/wrap"
	"log"
)

func iptableCmd(args ...string) error {
	cmd := "iptables"
	_, err := wrap.Command(cmd, args...).Output()
	if err != nil {
		log.Println("iptables command failed: ", args, err)
		return err
	}
	return nil
}

func ip6tableCmd(args ...string) error {
	cmd := "ip6tables"
	_, err := wrap.Command(cmd, args...).Output()
	if err != nil {
		log.Println("ip6tables command failed: ", args, err)
		return err
	}
	return nil
}

func iptablesInit() {
	// Avoid adding nat rule multiple times as we restart by flushing first
	iptableCmd("-t", "nat", "-F", "POSTROUTING")
	// Assumes ip rule for all underlay interfaces
	// XXX need to redo this when FreeUplinks changes
	for _, u := range globalConfig.FreeUplinks {
		iptableCmd("-t", "nat", "-A", "POSTROUTING", "-o", u,
			"-s", "172.27.0.0/16", "-j", "MASQUERADE")
	}
	// Flush IPv6 mangle rules from previous run
	ip6tableCmd("-F", "PREROUTING", "-t", "mangle")

	// Add mangle rules for IPv6 packets from dom0 overlay
	// since netfront/netback thinks there is checksum offload
	// XXX not needed once we have disaggregated dom0
	iptableCmd("-F", "POSTROUTING", "-t", "mangle")
	iptableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "tcp",
		"-j", "CHECKSUM", "--checksum-fill")
	iptableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "udp",
		"-j", "CHECKSUM", "--checksum-fill")
	ip6tableCmd("-F", "POSTROUTING", "-t", "mangle")
	ip6tableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "tcp",
		"-j", "CHECKSUM", "--checksum-fill")
	ip6tableCmd("-A", "POSTROUTING", "-t", "mangle", "-p", "udp",
		"-j", "CHECKSUM", "--checksum-fill")
}
