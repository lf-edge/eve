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

// SameIPVersions returns true if both IP addresses are of the same version
func SameIPVersions(ip1, ip2 net.IP) bool {
	firstIsV4 := ip1.To4() != nil
	secondIsV4 := ip2.To4() != nil
	return firstIsV4 == secondIsV4
}

// OverlappingSubnets returns true if the given subnets share at least one IP address.
func OverlappingSubnets(subnet1, subnet2 *net.IPNet) bool {
	if subnet1 == nil || len(subnet1.IP) == 0 ||
		subnet2 == nil || len(subnet2.IP) == 0 {
		// One of the subnets or both are undefined.
		return false
	}
	return subnet1.Contains(subnet2.IP) || subnet2.Contains(subnet1.IP)
}
