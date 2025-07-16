// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// GetDefaultGateway returns the default gateway IP address and the output interface.
func GetDefaultGateway(family int) (net.IP, netlink.Link, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		err = fmt.Errorf("failed to list IP routes: %w", err)
		return nil, nil, err
	}
	for _, route := range routes {
		if (route.Dst == nil || route.Dst.IP.IsUnspecified()) && route.Gw != nil {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				err = fmt.Errorf(
					"failed to resolve output interface for the default route: %w", err)
				return nil, nil, err
			}
			return route.Gw, link, nil
		}
	}
	return nil, nil, fmt.Errorf("default gateway IP not found")
}

// GetInterfaceIPs returns all IP addresses assigned to the given interface.
func GetInterfaceIPs(ifaceName string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses for %s: %w", ifaceName, err)
	}
	var ips []net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// GetEgressInterfaceForIP returns the output interface name for the given destination IP.
func GetEgressInterfaceForIP(ip net.IP) (string, error) {
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return "", fmt.Errorf("failed to get route to %s: %w", ip, err)
	}
	if len(routes) == 0 {
		return "", fmt.Errorf("no route found to %s", ip)
	}
	linkIndex := routes[0].LinkIndex
	link, err := netlink.LinkByIndex(linkIndex)
	if err != nil {
		return "", fmt.Errorf("failed to get link with index %d: %w",
			linkIndex, err)
	}
	return link.Attrs().Name, nil
}

// GetSubnetPrefixLen returns the prefix length (number of leading 1 bits)
// of the given subnet's mask.
func GetSubnetPrefixLen(subnet *net.IPNet) uint {
	ones, _ := subnet.Mask.Size()
	return uint(ones)
}

// GetNextIP returns the next IP in sequence.
func GetNextIP(ip net.IP) net.IP {
	n := make(net.IP, len(ip))
	copy(n, ip)

	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

// GetPrevIP returns the previous IP in sequence.
func GetPrevIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)

	for i := len(out) - 1; i >= 0; i-- {
		if out[i] > 0 {
			out[i]--
			break
		}
		out[i] = 0xff
	}
	return out
}

// GetFirstHostIP returns the IP address that should be assigned to the bridge
// or used as the default gateway.
// For IPv4 subnets, returns subnet network address + 1 (skips network address).
// For IPv6 subnets, returns the subnet prefix address itself (valid unicast address).
func GetFirstHostIP(subnet *net.IPNet) net.IP {
	if subnet == nil {
		return nil
	}

	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)

	// IPv4: skip network address
	if ip.To4() != nil {
		return GetNextIP(ip)
	}

	// IPv6: prefix address is usable
	return ip
}

// GetLastHostIP returns the last usable host IP address within the given subnet.
// For IPv4 subnets, this is the address immediately before the broadcast
// address (i.e. network | ^mask - 1).
// For IPv6 subnets, where there is no broadcast address, this returns the
// highest address in the subnet (network | ^mask).
func GetLastHostIP(subnet *net.IPNet) net.IP {
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)

	// Compute last address = network | ^mask
	for i := range ip {
		ip[i] |= ^subnet.Mask[i]
	}

	// Skip broadcast address (IPv4 semantics)
	if ip.To4() != nil {
		ip = GetPrevIP(ip)
	}
	return ip
}

// NewIPNet combines a given IP and subnet into net.IPNet.
// Returns nil if either the IP or subnet is nil.
func NewIPNet(ip net.IP, subnet *net.IPNet) *net.IPNet {
	if ip == nil || subnet == nil {
		return nil
	}
	return &net.IPNet{
		IP:   ip,
		Mask: subnet.Mask,
	}
}

// SplitIPv4Subnet splits an IPv4 subnet into two equal subnets.
func SplitIPv4Subnet(subnet *net.IPNet) (*net.IPNet, *net.IPNet, error) {
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return nil, nil, fmt.Errorf("not an IPv4 subnet: %s", subnet.String())
	}
	if ones == 32 {
		return nil, nil, fmt.Errorf("cannot split subnet %s further", subnet.String())
	}

	// new mask length
	newOnes := ones + 1
	newMask := net.CIDRMask(newOnes, 32)

	// first subnet: same base, new mask
	first := &net.IPNet{
		IP:   subnet.IP.Mask(newMask),
		Mask: newMask,
	}

	// second subnet: set the new bit in the base address
	secondIP := make(net.IP, len(subnet.IP))
	copy(secondIP, subnet.IP)
	bitIndex := ones
	byteIndex := bitIndex / 8
	bitInByte := 7 - (bitIndex % 8)
	secondIP[byteIndex] |= 1 << bitInByte

	second := &net.IPNet{
		IP:   secondIP.Mask(newMask),
		Mask: newMask,
	}
	return first, second, nil
}
