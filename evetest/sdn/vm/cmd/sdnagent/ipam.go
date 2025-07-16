// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math/big"
	"net"

	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/configitems"
	log "github.com/sirupsen/logrus"
)

var intOne = big.NewInt(1)
var internalIPv4Base, internalIPv6Base *ipAsInt
var internalIPv4Subnet, internalIPv6Subnet *net.IPNet

func init() {
	// 240.0.0.0/4 is reserved for internal use in SDN VM,
	// to allocate subnets between Network namespaces and the SDN Router.
	internalIPv4Base = ipToInt(net.ParseIP("240.0.0.0"))
	_, internalIPv4Subnet, _ = net.ParseCIDR("240.0.0.0/4")
	// fdfb:a84d:cb2a::/48 is reserved for internal use in SDN VM,
	// to allocate subnets between Network namespaces and the SDN Router.
	internalIPv6Base = ipToInt(net.ParseIP("fdfb:a84d:cb2a::"))
	_, internalIPv6Subnet, _ = net.ParseCIDR("fdfb:a84d:cb2a::/48")
}

type ipAsInt struct {
	num *big.Int
	len int // in bytes
	v4  bool
}

func ipToInt(ip net.IP) *ipAsInt {
	asInt := &ipAsInt{
		num: &big.Int{},
		v4:  len(ip) == net.IPv4len,
	}
	asInt.num.SetBytes(ip)
	if len(ip) == net.IPv4len || len(ip) == net.IPv6len {
		asInt.len = len(ip)
	} else {
		log.Fatalf("unsupported address length %d", len(ip))
	}
	return asInt
}

func getBroadcastIP(ipNet *net.IPNet) *ipAsInt {
	netIP := ipToInt(ipNet.IP)
	prefixLen, bits := ipNet.Mask.Size()
	hostLen := uint(bits) - uint(prefixLen)
	broadcastNum := big.NewInt(1)
	broadcastNum.Lsh(broadcastNum, hostLen)
	broadcastNum.Sub(broadcastNum, intOne)
	broadcastNum.Or(broadcastNum, netIP.num)
	return &ipAsInt{
		num: broadcastNum,
		len: netIP.len,
	}
}

func (ip *ipAsInt) Copy() *ipAsInt {
	return &ipAsInt{
		num: new(big.Int).Set(ip.num),
		len: ip.len,
	}
}

func (ip *ipAsInt) Equals(j *ipAsInt) bool {
	return ip.len == j.len && ip.num.Cmp(j.num) == 0
}

func (ip *ipAsInt) Inc(increment ...int) *ipAsInt {
	if len(increment) > 0 {
		ip.num.Add(ip.num, big.NewInt(int64(increment[0])))
		return ip
	}
	ip.num.Add(ip.num, intOne)
	return ip
}

func (ip *ipAsInt) Dec(decrement ...int) *ipAsInt {
	if len(decrement) > 0 {
		ip.num.Sub(ip.num, big.NewInt(int64(decrement[0])))
		return ip
	}
	ip.num.Sub(ip.num, intOne)
	return ip
}

func (ip *ipAsInt) ToIP() net.IP {
	ipBytes := ip.num.Bytes()
	ret := make([]byte, ip.len)
	// Pack our IP bytes into the end of the return array,
	// since big.Int.Bytes() removes front zero padding.
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}
	return ret
}

func (a *agent) genVethIPsForNetwork(logicalLabel string, ipv6 bool) (ip1, ip2 *net.IPNet) {
	index, hasIndex := a.networkIndex[logicalLabel]
	if !hasIndex {
		log.Fatalf("missing index for network %s", logicalLabel)
	}
	if ipv6 {
		// Each network is allocated /64 subnet for internally used veths.
		mask := net.CIDRMask(64, 128)
		base := internalIPv6Base.Copy()
		subnet := new(big.Int).Lsh(big.NewInt(int64(index)), 64)
		base.num.Or(base.num, subnet)
		ip1 = &net.IPNet{IP: base.Inc(1).ToIP(), Mask: mask}
		ip2 = &net.IPNet{IP: base.Inc(1).ToIP(), Mask: mask}
		return
	}

	// Each network is allocated /30 subnet for internally used veths.
	mask := net.CIDRMask(30, 32)
	base := internalIPv4Base.Copy()
	base.Inc(4 * index)
	ip1 = &net.IPNet{IP: base.Inc(1).ToIP(), Mask: mask}
	ip2 = &net.IPNet{IP: base.Inc(1).ToIP(), Mask: mask}
	return
}

func (a *agent) genEndpointGwIP(subnet *net.IPNet, epIP net.IP) (gwIP *net.IPNet) {
	epInt := ipToInt(epIP)
	gwInt := ipToInt(subnet.IP).Inc(1)
	if gwInt.Equals(epInt) {
		gwInt.Inc()
	}
	ip := gwInt.ToIP()
	if !subnet.Contains(ip) {
		// Should not be reachable.
		// Already validated that there is room for at least 2 hosts in the subnet.
		log.Fatalf("Not enough room in the subnet %v for gateway IP", subnet)
	}
	return &net.IPNet{IP: ip, Mask: subnet.Mask}
}

func (a *agent) subnetToHostIPRange(subnet *net.IPNet) configitems.IPRange {
	ones, bits := subnet.Mask.Size()
	hostBits := bits - ones
	if hostBits < 2 {
		return configitems.IPRange{
			FromIP: subnet.IP,
			ToIP:   subnet.IP,
		}
	}
	firstHost := ipToInt(subnet.IP).Inc()
	lastHost := getBroadcastIP(subnet).Dec()
	return configitems.IPRange{
		FromIP: firstHost.ToIP(),
		ToIP:   lastHost.ToIP(),
	}
}
