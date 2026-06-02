// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"net"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
)

func TestDeviceNetworkStatusToContract_NestsVLANs(t *testing.T) {
	eth0 := types.NetworkPortStatus{
		IfName:       "eth0",
		Logicallabel: "eth0",
		IsMgmt:       true,
		Up:           true,
		Cost:         0,
		Dhcp:         types.DhcpTypeClient,
		IPv4Subnet:   &net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)},
		AddrInfoList: []types.AddrInfo{
			{Addr: net.ParseIP("192.168.1.10")},
			{Addr: net.ParseIP("fe80::1")},      // link-local v6 -> dropped
			{Addr: net.ParseIP("2001:db8::10")}, // global v6 -> kept
		},
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
		DefaultRouters: []net.IP{net.ParseIP("192.168.1.1")},
	}
	eth0.ProxyConfig = types.ProxyConfig{
		NetworkProxyEnable: true,
		NetworkProxyURL:    "http://wpad/wpad.dat",
	}

	vlan := types.NetworkPortStatus{
		IfName:       "eth0.100",
		Logicallabel: "office-vlan",
		Up:           true,
		Dhcp:         types.DhcpTypeClient,
	}
	vlan.L2LinkConfig = types.L2LinkConfig{
		L2Type: types.L2LinkTypeVLAN,
		VLAN:   types.VLANConfig{ParentPort: "eth0", ID: 100},
	}

	got := deviceNetworkStatusToContract(types.DeviceNetworkStatus{
		Ports: []types.NetworkPortStatus{eth0, vlan},
	})

	if len(got.Interfaces) != 1 {
		t.Fatalf("expected 1 top-level interface (VLAN nested), got %d", len(got.Interfaces))
	}
	iface := got.Interfaces[0]
	if iface.Name != "eth0" || !iface.IsMgmt {
		t.Fatalf("unexpected interface: %+v", iface)
	}
	if _, ok := iface.Media.(monitorapi.MediaEthernet); !ok {
		t.Fatalf("expected ethernet media, got %T", iface.Media)
	}
	// addresses split by family, link-local v6 dropped.
	if len(iface.Network.IPv4) != 1 || iface.Network.IPv4[0].String() != "192.168.1.10" {
		t.Fatalf("unexpected ipv4: %v", iface.Network.IPv4)
	}
	if len(iface.Network.IPv6) != 1 || iface.Network.IPv6[0].String() != "2001:db8::10" {
		t.Fatalf("unexpected ipv6 (link-local should be dropped): %v", iface.Network.IPv6)
	}
	if iface.Network.Subnet == nil || iface.Network.Subnet.String() != "192.168.1.0/24" {
		t.Fatalf("unexpected subnet: %v", iface.Network.Subnet)
	}
	if _, ok := iface.Network.Proxy.(monitorapi.ProxyWpad); !ok {
		t.Fatalf("expected WPAD proxy, got %T", iface.Network.Proxy)
	}
	// VLAN nested under parent.
	if len(iface.VLANs) != 1 {
		t.Fatalf("expected 1 nested VLAN, got %d", len(iface.VLANs))
	}
	if v := iface.VLANs[0]; v.ID != 100 || v.Label != "office-vlan" || v.Name != "eth0.100" {
		t.Fatalf("unexpected VLAN: %+v", v)
	}
}

func TestProxyToContract_ManualByScheme(t *testing.T) {
	pc := types.ProxyConfig{
		Proxies: []types.ProxyEntry{
			{Type: types.NetworkProxyTypeHTTP, Server: "proxy", Port: 8080},
			{Type: types.NetworkProxyTypeHTTPS, Server: "proxy", Port: 8443},
		},
		Exceptions: "localhost, 127.0.0.1",
	}
	switch p := proxyToContract(pc).(type) {
	case monitorapi.ProxyManual:
		if len(p.Servers) != 2 || p.Servers[0].Scheme != monitorapi.ProxySchemeHTTP {
			t.Fatalf("unexpected servers: %+v", p.Servers)
		}
		if len(p.Exceptions) != 2 || p.Exceptions[1] != "127.0.0.1" {
			t.Fatalf("unexpected exceptions: %v", p.Exceptions)
		}
	default:
		t.Fatalf("expected ProxyManual, got %T", p)
	}
}
