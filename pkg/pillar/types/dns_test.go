// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// DeviceNetworkStatus.MostlyEqual — simple identical and different cases

func TestDeviceNetworkStatusMostlyEqual(t *testing.T) {
	// Both empty → equal
	s1 := DeviceNetworkStatus{}
	s2 := DeviceNetworkStatus{}
	assert.True(t, s1.MostlyEqual(s2))

	// Different port count → not equal
	s1.Ports = []NetworkPortStatus{{IfName: "eth0"}}
	assert.False(t, s1.MostlyEqual(s2))

	s2.Ports = []NetworkPortStatus{{IfName: "eth0"}}
	assert.True(t, s1.MostlyEqual(s2))

	// Different IfName → not equal
	s2.Ports[0].IfName = "eth1"
	assert.False(t, s1.MostlyEqual(s2))
}

// DeviceNetworkStatus.MostlyEqualStatus

func TestDeviceNetworkStatusMostlyEqualStatus(t *testing.T) {
	s1 := DeviceNetworkStatus{State: DPCStateSuccess}
	s2 := DeviceNetworkStatus{State: DPCStateSuccess}
	assert.True(t, s1.MostlyEqualStatus(s2))

	// Different state → not equal
	s2.State = DPCStateFail
	assert.False(t, s1.MostlyEqualStatus(s2))
}

// DeviceNetworkStatus.LookupPortsByLabel

func TestDeviceNetworkStatusLookupPortsByLabel(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", Logicallabel: "eth0label", SharedLabels: []string{"uplink"}},
			{IfName: "eth1", Logicallabel: "eth1label", SharedLabels: []string{"uplink", "mgmt"}},
			{IfName: "eth2", Logicallabel: "eth2label"},
		},
	}

	// Shared label "uplink" matches eth0 and eth1
	ports := dns.LookupPortsByLabel("uplink")
	require.Len(t, ports, 2)
	assert.Equal(t, "eth0", ports[0].IfName)
	assert.Equal(t, "eth1", ports[1].IfName)

	// Logical label match
	ports = dns.LookupPortsByLabel("eth2label")
	require.Len(t, ports, 1)
	assert.Equal(t, "eth2", ports[0].IfName)

	// No match
	assert.Len(t, dns.LookupPortsByLabel("missing"), 0)
}

// DeviceNetworkStatus.HasErrors

func TestDeviceNetworkStatusHasErrors(t *testing.T) {
	// No ports → no error
	assert.False(t, DeviceNetworkStatus{}.HasErrors())

	// Port with error: LastFailed > LastSucceeded indicates HasError
	now := time.Now()
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{TestResults: TestResults{LastFailed: now, LastError: "some error"}},
		},
	}
	assert.True(t, dns.HasErrors())

	// Clear error by setting LastSucceeded after LastFailed
	dns.Ports[0].TestResults.LastSucceeded = now.Add(time.Second)
	assert.False(t, dns.HasErrors())
}

// DeviceNetworkStatus.GetPortAddrInfo

func TestDeviceNetworkStatusGetPortAddrInfo(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", AddrInfoList: []AddrInfo{{Addr: ip1}, {Addr: ip2}}},
		},
	}

	got := dns.GetPortAddrInfo("eth0", ip1)
	require.NotNil(t, got)
	assert.True(t, got.Addr.Equal(ip1))

	assert.Nil(t, dns.GetPortAddrInfo("eth0", net.ParseIP("10.0.0.99")))
	assert.Nil(t, dns.GetPortAddrInfo("missing", ip1))
}
