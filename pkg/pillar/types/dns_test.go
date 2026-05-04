// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
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

// DeviceNetworkStatus.LookupPortByLogicallabel

func TestDeviceNetworkStatusLookupPortByLogicallabel(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", Logicallabel: "wan0"},
			{IfName: "eth1", Logicallabel: "wan1"},
		},
	}

	p := dns.LookupPortByLogicallabel("wan0")
	require.NotNil(t, p)
	assert.Equal(t, "eth0", p.IfName)

	p = dns.LookupPortByLogicallabel("wan1")
	require.NotNil(t, p)
	assert.Equal(t, "eth1", p.IfName)

	assert.Nil(t, dns.LookupPortByLogicallabel("missing"))
}

// IsPort

func TestIsPort(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0"},
			{IfName: "eth1"},
		},
	}

	assert.True(t, IsPort(dns, "eth0"))
	assert.True(t, IsPort(dns, "eth1"))
	assert.False(t, IsPort(dns, "eth2"))
}

// IsMgmtPort

func TestIsMgmtPort(t *testing.T) {
	dns := DeviceNetworkStatus{
		Version: DPCIsMgmt,
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true},
			{IfName: "eth1", IsMgmt: false},
		},
	}

	assert.True(t, IsMgmtPort(dns, "eth0"))
	assert.False(t, IsMgmtPort(dns, "eth1"))
	assert.False(t, IsMgmtPort(dns, "eth2"))
}

// GetPortCost

func TestGetPortCost(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", Cost: 5},
			{IfName: "eth1", Cost: 10},
		},
	}

	assert.Equal(t, uint8(5), GetPortCost(dns, "eth0"))
	assert.Equal(t, uint8(10), GetPortCost(dns, "eth1"))
	// Missing interface returns 0
	assert.Equal(t, uint8(0), GetPortCost(dns, "eth2"))
}

// GetMgmtPortFromAddr

func TestGetMgmtPortFromAddr(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("10.0.0.2")
	dns := DeviceNetworkStatus{
		Version: DPCIsMgmt,
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, AddrInfoList: []AddrInfo{{Addr: ip1}}},
			{IfName: "eth1", IsMgmt: false, AddrInfoList: []AddrInfo{{Addr: ip2}}},
		},
	}

	// Mgmt port with matching address
	assert.Equal(t, "eth0", GetMgmtPortFromAddr(dns, ip1))

	// Non-mgmt port skipped
	assert.Equal(t, "", GetMgmtPortFromAddr(dns, ip2))

	// Unknown address
	assert.Equal(t, "", GetMgmtPortFromAddr(dns, net.ParseIP("1.2.3.4")))
}

// CountDNSServers

func TestCountDNSServers(t *testing.T) {
	dns8 := net.ParseIP("8.8.8.8")
	dns1 := net.ParseIP("1.1.1.1")
	dns2 := net.ParseIP("9.9.9.9")
	d := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", DNSServers: []net.IP{dns8, dns1}},
			{IfName: "eth1", DNSServers: []net.IP{dns2}},
		},
	}

	// All ports
	assert.Equal(t, 3, CountDNSServers(d, ""))

	// Only eth0
	assert.Equal(t, 2, CountDNSServers(d, "eth0"))

	// Only eth1
	assert.Equal(t, 1, CountDNSServers(d, "eth1"))

	// Unknown interface
	assert.Equal(t, 0, CountDNSServers(d, "eth2"))
}

// GetMgmtPortsAny

func TestGetMgmtPortsAny(t *testing.T) {
	d := DeviceNetworkStatus{
		Version: DPCIsMgmt,
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsL3Port: true, IsMgmt: true},
			{IfName: "eth1", IsL3Port: true, IsMgmt: false},
			{IfName: "eth2", IsL3Port: false, IsMgmt: true},
		},
	}

	ports := GetMgmtPortsAny(d, 0)
	// Only L3 mgmt ports returned
	assert.Contains(t, ports, "eth0")
	assert.NotContains(t, ports, "eth1")
}

// GetMgmtPortsSortedCostWithoutFailed

func TestGetMgmtPortsSortedCostWithoutFailed(t *testing.T) {
	now := time.Now()
	d := DeviceNetworkStatus{
		Version: DPCIsMgmt,
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsL3Port: true, IsMgmt: true, Cost: 0},
			{IfName: "eth1", IsL3Port: true, IsMgmt: true, Cost: 10,
				TestResults: TestResults{LastFailed: now, LastError: "err"}},
		},
	}

	ports := GetMgmtPortsSortedCostWithoutFailed(d, 0)
	// eth1 has a failure so it should be dropped
	assert.Contains(t, ports, "eth0")
	assert.NotContains(t, ports, "eth1")
}

// DeviceNetworkStatus.UpdatePortStatusFromIntfStatusMap

func TestDeviceNetworkStatusUpdatePortStatusFromIntfStatusMap(t *testing.T) {
	now := time.Now()
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0"},
			{IfName: "eth1"},
		},
	}
	statusMap := IntfStatusMap{
		StatusMap: map[string]TestResults{
			"eth0": {LastSucceeded: now, LastError: ""},
		},
	}
	dns.UpdatePortStatusFromIntfStatusMap(statusMap)

	// eth0 should be updated
	assert.Equal(t, now, dns.Ports[0].TestResults.LastSucceeded)
	// eth1 was not in map, unchanged
	assert.True(t, dns.Ports[1].TestResults.LastSucceeded.IsZero())
}

// GetDNSServers

func TestGetDNSServers(t *testing.T) {
	dns8 := net.ParseIP("8.8.8.8")
	dns1 := net.ParseIP("1.1.1.1")
	d := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, DNSServers: []net.IP{dns8, dns1}},
			{IfName: "eth1", IsMgmt: false, DNSServers: []net.IP{dns8}},
		},
	}

	// No ifname filter: only mgmt ports
	servers := GetDNSServers(d, "")
	assert.Len(t, servers, 2)

	// Specific ifname: get servers for that port (regardless of mgmt)
	servers = GetDNSServers(d, "eth1")
	assert.Len(t, servers, 1)
	assert.True(t, servers[0].Equal(dns8))

	// Unknown ifname
	servers = GetDNSServers(d, "eth2")
	assert.Len(t, servers, 0)
}

// DeviceNetworkStatus.MostlyEqualStatus — additional branches

func TestDeviceNetworkStatusMostlyEqualStatusWithPorts(t *testing.T) {
	now := time.Now()
	s1 := DeviceNetworkStatus{
		State:        DPCStateSuccess,
		CurrentIndex: 0,
		Ports:        []NetworkPortStatus{{IfName: "eth0"}},
	}

	// Identical → equal
	s2 := DeviceNetworkStatus{
		State:        DPCStateSuccess,
		CurrentIndex: 0,
		Ports:        []NetworkPortStatus{{IfName: "eth0"}},
	}
	assert.True(t, s1.MostlyEqualStatus(s2))

	// Different CurrentIndex → not equal
	s2.CurrentIndex = 1
	assert.False(t, s1.MostlyEqualStatus(s2))

	// Port changes to error state → not equal (independent port slices)
	s3 := DeviceNetworkStatus{
		State:        DPCStateSuccess,
		CurrentIndex: 0,
		Ports:        []NetworkPortStatus{{IfName: "eth0", TestResults: TestResults{LastFailed: now, LastError: "link down"}}},
	}
	assert.False(t, s1.MostlyEqualStatus(s3))

	// MostlyEqual itself returns false → first if in MostlyEqualStatus triggers
	s4 := DeviceNetworkStatus{
		State: DPCStateSuccess,
		Ports: []NetworkPortStatus{{IfName: "eth1"}}, // different IfName → MostlyEqual=false
	}
	assert.False(t, s1.MostlyEqualStatus(s4))

	// Different port count → len check triggers
	s5 := DeviceNetworkStatus{
		State: DPCStateSuccess,
		Ports: []NetworkPortStatus{{IfName: "eth0"}, {IfName: "eth1"}},
	}
	assert.False(t, s1.MostlyEqualStatus(s5))
}

// DeviceNetworkStatus.MostlyEqual — port content diff

func TestDeviceNetworkStatusMostlyEqualPortContent(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	s1 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, IPv4Subnet: subnet},
		},
	}

	// Identical
	s2 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, IPv4Subnet: subnet},
		},
	}
	assert.True(t, s1.MostlyEqual(s2))

	// Different DNS servers
	s3 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, IPv4Subnet: subnet, DNSServers: []net.IP{net.ParseIP("8.8.8.8")}},
		},
	}
	assert.False(t, s1.MostlyEqual(s3))

	// Different IPv4Subnet
	_, subnet2, _ := net.ParseCIDR("10.0.0.0/8")
	s4 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true, IPv4Subnet: subnet2},
		},
	}
	assert.False(t, s1.MostlyEqual(s4))
}

// DeviceNetworkStatus.MostlyEqual — remaining branches

func TestDeviceNetworkStatusMostlyEqualRemainingBranches(t *testing.T) {
	// NtpServers diff
	s1 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", NtpServers: []netutils.HostnameOrIP{netutils.NewHostnameOrIP("192.168.1.1")}},
		},
	}
	s2 := DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0"}}}
	assert.False(t, s1.MostlyEqual(s2))

	// AddrInfoList diff
	s1 = DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", AddrInfoList: []AddrInfo{{Addr: net.ParseIP("192.168.1.1")}}},
		},
	}
	s2 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0"}}}
	assert.False(t, s1.MostlyEqual(s2))

	// ClusterIPAddr diff
	s1 = DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", ClusterIPAddr: net.ParseIP("10.0.0.1")},
		},
	}
	s2 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0"}}}
	assert.False(t, s1.MostlyEqual(s2))

	// Up diff
	s1 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0", Up: true}}}
	s2 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0", Up: false}}}
	assert.False(t, s1.MostlyEqual(s2))

	// DefaultRouters diff
	s1 = DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", DefaultRouters: []net.IP{net.ParseIP("192.168.1.1")}},
		},
	}
	s2 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0"}}}
	assert.False(t, s1.MostlyEqual(s2))

	// PNAC.Enabled diff
	s1 = DeviceNetworkStatus{
		Ports: []NetworkPortStatus{{IfName: "eth0", PNAC: PNACStatus{Enabled: true}}},
	}
	s2 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0"}}}
	assert.False(t, s1.MostlyEqual(s2))

	// RadioSilence diff (final return)
	s1 = DeviceNetworkStatus{RadioSilence: RadioSilence{Imposed: true}}
	s2 = DeviceNetworkStatus{}
	assert.False(t, s1.MostlyEqual(s2))

	// All equal → true (exercises the final return true path)
	s1 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0", Up: true}}}
	s2 = DeviceNetworkStatus{Ports: []NetworkPortStatus{{IfName: "eth0", Up: true}}}
	assert.True(t, s1.MostlyEqual(s2))
}

// GetPort

func TestGetPort(t *testing.T) {
	// Not found → nil
	dns := DeviceNetworkStatus{
		Version: DPCIsMgmt,
		Ports:   []NetworkPortStatus{{IfName: "eth0"}},
	}
	assert.Nil(t, GetPort(dns, "missing"))

	// Found, version >= DPCIsMgmt → IsMgmt not forced
	port := GetPort(dns, "eth0")
	require.NotNil(t, port)
	assert.Equal(t, "eth0", port.IfName)
	assert.False(t, port.IsMgmt) // was false, stays false

	// Old DPC version → IsMgmt forced to true
	dns.Version = DPCInitial
	port = GetPort(dns, "eth0")
	require.NotNil(t, port)
	assert.True(t, port.IsMgmt)
}

// getLocalAddrImpl error path — named interface not found triggers error return
func TestGetLocalAddrImplErrorPath(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", IsMgmt: true},
		},
	}
	// Request a specific interface that does not exist → getLocalAddrListImpl returns error
	_, err := GetLocalAddrAnyNoLinkLocal(dns, 0, "nonexistent0")
	assert.Error(t, err)
}

// getLocalAddrIf nil Addr — safety continue branch when Addr is nil
func TestGetLocalAddrIfNilAddr(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{
				IfName: "eth0",
				IsMgmt: true,
				// AddrInfo with a nil Addr — skipped by the nil check
				AddrInfoList: []AddrInfo{{Addr: nil}},
			},
		},
	}
	// All addresses are nil → no valid addresses → error
	_, err := GetLocalAddrAnyNoLinkLocal(dns, 0, "eth0")
	assert.Error(t, err)
}

// getLocalAddrImpl no-addresses — covers the numAddrs==0 return path
func TestGetLocalAddrImplNoAddresses(t *testing.T) {
	// DNS with no ports at all → getLocalAddrListImpl with ifname="" returns empty, nil
	// → numAddrs==0 → "no addresses" error
	dns := DeviceNetworkStatus{}
	_, err := GetLocalAddrAnyNoLinkLocal(dns, 0, "")
	assert.Error(t, err)
}

// getLocalAddrIf case 6 — IPv6-only filter; IPv4 addresses are skipped
func TestGetLocalAddrIfIPv6Only(t *testing.T) {
	ipv4Addr := net.ParseIP("192.168.1.1")
	ipv6Addr := net.ParseIP("2001:db8::1")
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{
				IfName: "eth0",
				AddrInfoList: []AddrInfo{
					{Addr: ipv4Addr}, // IPv4 — filtered out by af=6
					{Addr: ipv6Addr}, // IPv6 — accepted by af=6
				},
			},
		},
	}
	// Call getLocalAddrIf directly with af=6
	addrs, err := getLocalAddrIf(dns, "eth0", false, 6)
	require.NoError(t, err)
	require.Len(t, addrs, 1)
	assert.True(t, addrs[0].Equal(ipv6Addr))
}

// MostlyEqual AddrInfo closure — covers the EqualSetsFn closure body
func TestMostlyEqualAddrInfoClosure(t *testing.T) {
	addr := net.ParseIP("192.168.1.1")
	s1 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", AddrInfoList: []AddrInfo{{Addr: addr}}},
		},
	}
	// Same AddrInfo → equal (closure executes and returns true)
	s2 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", AddrInfoList: []AddrInfo{{Addr: addr}}},
		},
	}
	assert.True(t, s1.MostlyEqual(s2))

	// Different AddrInfo → not equal (closure executes and returns false)
	s3 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", AddrInfoList: []AddrInfo{{Addr: net.ParseIP("10.0.0.1")}}},
		},
	}
	assert.False(t, s1.MostlyEqual(s3))
}

// MostlyEqual BondStatus diff — covers the !BondStatus.Equal return false branch
func TestMostlyEqualBondStatusDiff(t *testing.T) {
	s1 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", BondStatus: BondStatus{ActiveMember: "eth1"}},
		},
	}
	s2 := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			{IfName: "eth0", BondStatus: BondStatus{ActiveMember: "eth2"}},
		},
	}
	assert.False(t, s1.MostlyEqual(s2))
}

// DeviceNetworkStatus.LogKey — covers the LogKey() function body
func TestDeviceNetworkStatusLogKey(t *testing.T) {
	dns := DeviceNetworkStatus{}
	key := dns.LogKey()
	assert.Contains(t, key, dns.Key())
}
