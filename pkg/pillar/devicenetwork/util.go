// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"net"
	"syscall"
)

// HostFamily returns the address family for the given IP address
func HostFamily(ip net.IP) int {
	if ip.To4() != nil {
		return syscall.AF_INET
	} else {
		return syscall.AF_INET6
	}
}

// HostSubnet returns the subnet mask for the given IP address
func HostSubnet(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	} else {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
}
