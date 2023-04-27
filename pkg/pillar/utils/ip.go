// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"net"
)

// EqualIPs compares two IP addresses.
func EqualIPs(ip1 net.IP, ip2 net.IP) bool {
	if ip1 == nil {
		return ip2 == nil
	}
	if ip2 == nil {
		return ip1 == nil
	}
	return ip1.Equal(ip2)
}

// EqualIPNets compares two IP addresses with masks.
func EqualIPNets(ipNet1, ipNet2 *net.IPNet) bool {
	if ipNet1 == nil || ipNet2 == nil {
		return ipNet1 == ipNet2
	}
	return ipNet1.IP.Equal(ipNet2.IP) &&
		bytes.Equal(ipNet1.Mask, ipNet2.Mask)
}
