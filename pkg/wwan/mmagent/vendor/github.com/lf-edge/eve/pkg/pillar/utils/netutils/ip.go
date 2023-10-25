// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netutils

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

// AddToIP increments IP address by the given integer number.
func AddToIP(ip net.IP, addition int) net.IP {
	if addr := ip.To4(); addr != nil {
		val := uint32(addr[0])<<24 + uint32(addr[1])<<16 +
			uint32(addr[2])<<8 + uint32(addr[3])
		val += uint32(addition)
		byte0 := byte((val >> 24) & 0xFF)
		byte1 := byte((val >> 16) & 0xFF)
		byte2 := byte((val >> 8) & 0xFF)
		byte3 := byte(val & 0xFF)
		return net.IPv4(byte0, byte1, byte2, byte3)
	}
	//TBD:XXX, IPv6 handling
	return net.IP{}
}

// GetIPAddrCountOnSubnet return the number or available IP addresses inside a subnet.
func GetIPAddrCountOnSubnet(subnet net.IPNet) int {
	prefixLen, _ := subnet.Mask.Size()
	if prefixLen != 0 {
		if subnet.IP.To4() != nil {
			return 0x01 << (32 - prefixLen)
		}
		if subnet.IP.To16() != nil {
			return 0x01 << (128 - prefixLen)
		}
	}
	return 0
}

// GetIPNetwork returns the first IP Address of the subnet(Network Address)
func GetIPNetwork(subnet net.IPNet) net.IP {
	return subnet.IP.Mask(subnet.Mask)
}

// GetIPBroadcast returns the last IP Address of the subnet(Broadcast Address)
func GetIPBroadcast(subnet net.IPNet) net.IP {
	if network := GetIPNetwork(subnet); network != nil {
		if addrCount := GetIPAddrCountOnSubnet(subnet); addrCount != 0 {
			return AddToIP(network, addrCount-1)
		}
	}
	return net.IP{}
}
