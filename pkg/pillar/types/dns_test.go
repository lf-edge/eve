// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// NetworkPortStatus.HasIPAndDNS

func TestNetworkPortStatusHasIPAndDNS(t *testing.T) {
	globalIP := net.ParseIP("192.168.1.10")
	linkLocalIP := net.ParseIP("169.254.1.1")
	gateway := net.ParseIP("192.168.1.1")
	dnsServer := net.ParseIP("8.8.8.8")

	// No addresses at all
	port := NetworkPortStatus{}
	assert.False(t, port.HasIPAndDNS())

	// Only link-local address — does not count as unicast
	port = NetworkPortStatus{
		AddrInfoList:   []AddrInfo{{Addr: linkLocalIP}},
		DefaultRouters: []net.IP{gateway},
		DNSServers:     []net.IP{dnsServer},
	}
	assert.False(t, port.HasIPAndDNS())

	// Global IP but no routers
	port = NetworkPortStatus{
		AddrInfoList: []AddrInfo{{Addr: globalIP}},
		DNSServers:   []net.IP{dnsServer},
	}
	assert.False(t, port.HasIPAndDNS())

	// Global IP but no DNS
	port = NetworkPortStatus{
		AddrInfoList:   []AddrInfo{{Addr: globalIP}},
		DefaultRouters: []net.IP{gateway},
	}
	assert.False(t, port.HasIPAndDNS())

	// All three present
	port = NetworkPortStatus{
		AddrInfoList:   []AddrInfo{{Addr: globalIP}},
		DefaultRouters: []net.IP{gateway},
		DNSServers:     []net.IP{dnsServer},
	}
	assert.True(t, port.HasIPAndDNS())
}

// DeviceNetworkStatus.IsPortUsedAsVlanParent

func TestDeviceNetworkStatusIsPortUsedAsVlanParent(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{
				IfName:       "eth0",
				Logicallabel: "eth0label",
			},
			{
				IfName:       "eth0.100",
				Logicallabel: "vlan100",
				L2LinkConfig: L2LinkConfig{
					L2Type: L2LinkTypeVLAN,
					VLAN:   VLANConfig{ParentPort: "eth0label", ID: 100},
				},
			},
		},
	}

	assert.True(t, dns.IsPortUsedAsVlanParent("eth0label"))
	assert.False(t, dns.IsPortUsedAsVlanParent("vlan100"))
	assert.False(t, dns.IsPortUsedAsVlanParent("missing"))
}

// IsL3Port

func TestIsL3Port(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsL3Port: true},
			{IfName: "eth1", IsL3Port: false},
		},
	}

	assert.True(t, IsL3Port(dns, "eth0"))
	assert.False(t, IsL3Port(dns, "eth1"))
	assert.False(t, IsL3Port(dns, "missing"))
}
