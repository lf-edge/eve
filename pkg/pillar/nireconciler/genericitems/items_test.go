// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	dg "github.com/lf-edge/eve-libs/depgraph"
	uuid "github.com/satori/go.uuid"
)

func mustParseCIDRGen(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// --- Pure helper functions ---

func TestEqualUpstreamDNSServer(t *testing.T) {
	a := UpstreamDNSServer{IPAddress: net.IP{1, 1, 1, 1}, Port: NetworkIf{IfName: "eth0"}}
	b := UpstreamDNSServer{IPAddress: net.IP{1, 1, 1, 1}, Port: NetworkIf{IfName: "eth0"}}
	diffIP := UpstreamDNSServer{IPAddress: net.IP{8, 8, 8, 8}, Port: NetworkIf{IfName: "eth0"}}
	diffPort := UpstreamDNSServer{IPAddress: net.IP{1, 1, 1, 1}, Port: NetworkIf{IfName: "eth1"}}
	if !equalUpstreamDNSServer(a, b) {
		t.Error("identical servers should be equal")
	}
	if equalUpstreamDNSServer(a, diffIP) {
		t.Error("different IP should be unequal")
	}
	if equalUpstreamDNSServer(a, diffPort) {
		t.Error("different Port should be unequal")
	}
}

func TestEqualMACToIP(t *testing.T) {
	a := MACToIP{MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, IP: net.IP{10, 0, 0, 5}, Hostname: "app1"}
	b := MACToIP{MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, IP: net.IP{10, 0, 0, 5}, Hostname: "app1"}
	diffMAC := MACToIP{MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}, IP: net.IP{10, 0, 0, 5}, Hostname: "app1"}
	diffHostname := MACToIP{MAC: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, IP: net.IP{10, 0, 0, 5}, Hostname: "app2"}
	if !equalMACToIP(a, b) {
		t.Error("identical entries should be equal")
	}
	if equalMACToIP(a, diffMAC) {
		t.Error("different MAC should be unequal")
	}
	if equalMACToIP(a, diffHostname) {
		t.Error("different Hostname should be unequal")
	}
}

func TestEqualIPRoutes(t *testing.T) {
	r1 := IPRoute{DstNetwork: mustParseCIDRGen("192.168.1.0/24"), Gateway: net.IP{10, 0, 0, 1}}
	r2 := IPRoute{DstNetwork: mustParseCIDRGen("192.168.1.0/24"), Gateway: net.IP{10, 0, 0, 1}}
	r3 := IPRoute{DstNetwork: mustParseCIDRGen("10.0.0.0/8"), Gateway: net.IP{10, 0, 0, 1}}
	r4 := IPRoute{DstNetwork: mustParseCIDRGen("192.168.1.0/24"), Gateway: net.IP{10, 0, 1, 1}}
	if !EqualIPRoutes(r1, r2) {
		t.Error("identical routes should be equal")
	}
	if EqualIPRoutes(r1, r3) {
		t.Error("different dst should be unequal")
	}
	if EqualIPRoutes(r1, r4) {
		t.Error("different gw should be unequal")
	}
}

func TestEqualHostnameToIP(t *testing.T) {
	a := HostnameToIPs{Hostname: "host", IPs: []net.IP{{10, 0, 0, 1}}}
	b := HostnameToIPs{Hostname: "host", IPs: []net.IP{{10, 0, 0, 1}}}
	diffHost := HostnameToIPs{Hostname: "other", IPs: []net.IP{{10, 0, 0, 1}}}
	diffIP := HostnameToIPs{Hostname: "host", IPs: []net.IP{{10, 0, 0, 2}}}
	if !equalHostnameToIP(a, b) {
		t.Error("identical entries should be equal")
	}
	if equalHostnameToIP(a, diffHost) {
		t.Error("different hostname should be unequal")
	}
	if equalHostnameToIP(a, diffIP) {
		t.Error("different IP should be unequal")
	}
}

func TestEqualLinuxIPSet(t *testing.T) {
	a := LinuxIPSet{Domains: []string{"a.com"}, Sets: []string{"s1", "s2"}}
	b := LinuxIPSet{Domains: []string{"a.com"}, Sets: []string{"s2", "s1"}} // order-independent
	c := LinuxIPSet{Domains: []string{"b.com"}, Sets: []string{"s1", "s2"}}
	d := LinuxIPSet{Domains: []string{"a.com"}, Sets: []string{"s1"}}
	if !equalLinuxIPSet(a, b) {
		t.Error("set equality should be order-independent")
	}
	if equalLinuxIPSet(a, c) {
		t.Error("different domains should be unequal")
	}
	if equalLinuxIPSet(a, d) {
		t.Error("different set count should be unequal")
	}
}

func TestIsECONNREFUSED(t *testing.T) {
	if isECONNREFUSED(fmt.Errorf("plain error")) {
		t.Error("plain error should not be ECONNREFUSED")
	}
	opErr := &net.OpError{
		Op:  "dial",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	}
	if !isECONNREFUSED(opErr) {
		t.Error("ECONNREFUSED error should be detected")
	}
	opErrOther := &net.OpError{
		Op:  "dial",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNRESET},
	}
	if isECONNREFUSED(opErrOther) {
		t.Error("ECONNRESET should not be ECONNREFUSED")
	}
}

// --- DnsmasqConfigurator path helpers ---

func TestDnsmasqConfiguratorPaths(t *testing.T) {
	c := &DnsmasqConfigurator{}
	tests := []struct {
		fn   func(string) string
		arg  string
		want string
	}{
		{c.dnsmasqConfigPath, "br0", "/run/zedrouter/dnsmasq.br0.conf"},
		{c.dnsmasqPidFile, "br0", "/run/zedrouter/dnsmasq.br0.pid"},
		{c.dnsmasqDHCPHostsDir, "br0", "/run/zedrouter/dhcp-hosts.br0"},
		{c.dnsmasqDNSHostsDir, "br0", "/run/zedrouter/hosts.br0"},
	}
	for _, tc := range tests {
		if got := tc.fn(tc.arg); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestDhcpTagForHost(t *testing.T) {
	c := &DnsmasqConfigurator{}
	gwIP := net.IP{10, 0, 0, 100}
	dhcpSrv := DHCPServer{
		PropagateRoutes: []IPRoute{
			{DstNetwork: mustParseCIDRGen("192.168.1.0/24"), Gateway: gwIP},
		},
	}
	if got := c.dhcpTagForHost(dhcpSrv, gwIP); got != "gateway-10-0-0-100" {
		t.Errorf("gateway host tag: got %q, want %q", got, "gateway-10-0-0-100")
	}
	endpointIP := net.IP{10, 0, 0, 5}
	if got := c.dhcpTagForHost(dhcpSrv, endpointIP); got != endpointTag {
		t.Errorf("endpoint host tag: got %q, want %q", got, endpointTag)
	}
}

func TestGetAppGatewayTag(t *testing.T) {
	c := &DnsmasqConfigurator{}
	tests := []struct {
		ip   net.IP
		want string
	}{
		{net.IP{10, 0, 0, 100}, "gateway-10-0-0-100"},
		{net.IP{10, 0, 1, 1}, "gateway-10-0-1-1"},
	}
	for _, tc := range tests {
		if got := c.getAppGatewayTag(tc.ip); got != tc.want {
			t.Errorf("getAppGatewayTag(%v): got %q, want %q", tc.ip, got, tc.want)
		}
	}
}

// --- RadvdConfigurator path helpers ---

func TestRadvdConfiguratorPaths(t *testing.T) {
	c := &RadvdConfigurator{}
	if got := c.radvdConfigPath("br0"); got != "/run/zedrouter/radvd.br0.conf" {
		t.Errorf("radvdConfigPath: got %q", got)
	}
	if got := c.radvdPidFile("br0"); got != "/run/zedrouter/radvd.br0.pid" {
		t.Errorf("radvdPidFile: got %q", got)
	}
}

// --- Dnsmasq item ---

func TestDnsmasqEqual(t *testing.T) {
	ni1 := uuid.Must(uuid.NewV4())
	ni2 := uuid.Must(uuid.NewV4())
	d1 := Dnsmasq{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0"}}
	d2Same := Dnsmasq{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0"}}
	d3DiffNI := Dnsmasq{ForNI: ni2, ListenIf: NetworkIf{IfName: "br0"}}
	d4DiffIf := Dnsmasq{ForNI: ni1, ListenIf: NetworkIf{IfName: "br1"}}
	if !d1.Equal(d2Same) {
		t.Error("identical Dnsmasq instances should be equal")
	}
	if d1.Equal(d3DiffNI) {
		t.Error("different ForNI should be unequal")
	}
	if d1.Equal(d4DiffIf) {
		t.Error("different ListenIf should be unequal")
	}
}

func TestDnsmasqDependencies(t *testing.T) {
	listenIP := net.IP{10, 0, 0, 1}
	listenRef := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	portRef := dg.ItemRef{ItemType: PortTypename, ItemName: "eth0"}
	d := Dnsmasq{
		ListenIf: NetworkIf{IfName: "br0", ItemRef: listenRef},
		DNSServer: DNSServer{
			ListenIP: listenIP,
			UpstreamServers: []UpstreamDNSServer{
				{IPAddress: net.IP{1, 1, 1, 1}, Port: NetworkIf{IfName: "eth0", ItemRef: portRef}},
			},
			LinuxIPSets: []LinuxIPSet{
				{Sets: []string{"ipv4.test.com"}},
			},
		},
	}
	deps := d.Dependencies()
	if len(deps) < 3 {
		t.Fatalf("expected at least 3 deps (listenIf + port + ipset), got %d", len(deps))
	}
	// First dep: ListenIf
	if deps[0].RequiredItem != listenRef {
		t.Errorf("first dep should be ListenIf")
	}
	if deps[0].MustSatisfy == nil {
		t.Error("ListenIf dep should have MustSatisfy")
	}
	// MustSatisfy: Port with matching IP → true
	matchingPort := Port{IPAddresses: []*net.IPNet{{IP: listenIP, Mask: net.CIDRMask(24, 32)}}}
	if !deps[0].MustSatisfy(matchingPort) {
		t.Error("MustSatisfy should return true when listenIP matches")
	}
	// MustSatisfy: Port without matching IP → false
	noMatchPort := Port{IPAddresses: []*net.IPNet{{IP: net.IP{10, 0, 1, 1}, Mask: net.CIDRMask(24, 32)}}}
	if deps[0].MustSatisfy(noMatchPort) {
		t.Error("MustSatisfy should return false when IP does not match")
	}
	// MustSatisfy: non-NetworkIfWithIP item → false
	if deps[0].MustSatisfy(Radvd{}) {
		t.Error("MustSatisfy should return false for non-NetworkIfWithIP item")
	}
	// Last dep: IPSet
	lastDep := deps[len(deps)-1]
	if lastDep.RequiredItem.ItemType != IPSetTypename {
		t.Errorf("last dep should be IPSet, got %q", lastDep.RequiredItem.ItemType)
	}
}

// --- HTTPServer item ---

func TestHTTPServerEqual(t *testing.T) {
	ni1 := uuid.Must(uuid.NewV4())
	ni2 := uuid.Must(uuid.NewV4())
	ref := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	s1 := HTTPServer{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0", ItemRef: ref},
		ListenIP: net.IP{10, 0, 0, 1}, Port: 8080}
	s2Same := HTTPServer{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0", ItemRef: ref},
		ListenIP: net.IP{10, 0, 0, 1}, Port: 8080}
	s3DiffNI := HTTPServer{ForNI: ni2, ListenIf: NetworkIf{IfName: "br0", ItemRef: ref},
		ListenIP: net.IP{10, 0, 0, 1}, Port: 8080}
	s4DiffPort := HTTPServer{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0", ItemRef: ref},
		ListenIP: net.IP{10, 0, 0, 1}, Port: 9090}
	if !s1.Equal(s2Same) {
		t.Error("identical HTTPServer instances should be equal")
	}
	if s1.Equal(s3DiffNI) {
		t.Error("different ForNI should be unequal")
	}
	if s1.Equal(s4DiffPort) {
		t.Error("different Port should be unequal")
	}
}

func TestHTTPServerDependencies(t *testing.T) {
	listenIP := net.IP{10, 0, 0, 1}
	listenRef := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	s := HTTPServer{
		ListenIf: NetworkIf{IfName: "br0", ItemRef: listenRef},
		ListenIP: listenIP,
		Port:     8080,
	}
	deps := s.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem != listenRef {
		t.Errorf("dep should be ListenIf")
	}
	if deps[0].MustSatisfy == nil {
		t.Error("dep should have MustSatisfy")
	}
	matchingPort := Port{IPAddresses: []*net.IPNet{{IP: listenIP, Mask: net.CIDRMask(24, 32)}}}
	if !deps[0].MustSatisfy(matchingPort) {
		t.Error("MustSatisfy should return true when listenIP matches")
	}
	noMatchPort := Port{IPAddresses: []*net.IPNet{{IP: net.IP{10, 0, 1, 1}, Mask: net.CIDRMask(24, 32)}}}
	if deps[0].MustSatisfy(noMatchPort) {
		t.Error("MustSatisfy should return false when IP does not match")
	}
}

// --- IPReserve item ---

func TestIPReserveDependencies(t *testing.T) {
	r := IPReserve{AddrWithMask: &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestIPReserveEqual(t *testing.T) {
	ip1 := &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}
	ip2 := &net.IPNet{IP: net.IP{10, 0, 1, 1}, Mask: net.CIDRMask(24, 32)}
	ref := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	r1 := IPReserve{AddrWithMask: ip1, NetIf: NetworkIf{IfName: "br0", ItemRef: ref}}
	r2Same := IPReserve{AddrWithMask: ip1, NetIf: NetworkIf{IfName: "br0", ItemRef: ref}}
	r3DiffIP := IPReserve{AddrWithMask: ip2, NetIf: NetworkIf{IfName: "br0", ItemRef: ref}}
	r4DiffIf := IPReserve{AddrWithMask: ip1, NetIf: NetworkIf{IfName: "br1"}}
	r5WrongType := Port{}
	tests := []struct {
		name  string
		other dg.Item
		want  bool
	}{
		{"identical", r2Same, true},
		{"different IP", r3DiffIP, false},
		{"different NetIf", r4DiffIf, false},
		{"wrong type", r5WrongType, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := r1.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Port item ---

func TestPortDependencies(t *testing.T) {
	p := Port{}
	if deps := p.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestPortGetAssignedIPs(t *testing.T) {
	ip1 := &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}
	ip2 := &net.IPNet{IP: net.IP{192, 168, 1, 1}, Mask: net.CIDRMask(24, 32)}
	p := Port{IPAddresses: []*net.IPNet{ip1, ip2}}
	ips := p.GetAssignedIPs()
	if len(ips) != 2 {
		t.Errorf("GetAssignedIPs: got %d IPs, want 2", len(ips))
	}
}

func TestPortEqual(t *testing.T) {
	ip1 := &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}
	ip2 := &net.IPNet{IP: net.IP{10, 0, 1, 1}, Mask: net.CIDRMask(24, 32)}
	p1 := Port{IfName: "eth0", LogicalLabel: "uplink", AdminUp: true, IPAddresses: []*net.IPNet{ip1}}
	p2Same := Port{IfName: "eth0", LogicalLabel: "uplink", AdminUp: true, IPAddresses: []*net.IPNet{ip1}}
	p3DiffName := Port{IfName: "eth1", LogicalLabel: "uplink", AdminUp: true, IPAddresses: []*net.IPNet{ip1}}
	p4DiffIPs := Port{IfName: "eth0", LogicalLabel: "uplink", AdminUp: true, IPAddresses: []*net.IPNet{ip2}}
	p5WrongType := IPReserve{AddrWithMask: ip1}
	tests := []struct {
		name  string
		other dg.Item
		want  bool
	}{
		{"identical", p2Same, true},
		{"different IfName", p3DiffName, false},
		{"different IPs", p4DiffIPs, false},
		{"wrong type", p5WrongType, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := p1.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Radvd item ---

func TestRadvdEqual(t *testing.T) {
	ni1 := uuid.Must(uuid.NewV4())
	ni2 := uuid.Must(uuid.NewV4())
	r1 := Radvd{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0"}, MTU: 1500}
	r2Same := Radvd{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0"}, MTU: 1500}
	r3DiffNI := Radvd{ForNI: ni2, ListenIf: NetworkIf{IfName: "br0"}, MTU: 1500}
	r4DiffMTU := Radvd{ForNI: ni1, ListenIf: NetworkIf{IfName: "br0"}, MTU: 9000}
	if !r1.Equal(r2Same) {
		t.Error("identical Radvd instances should be equal")
	}
	if r1.Equal(r3DiffNI) {
		t.Error("different ForNI should be unequal")
	}
	if r1.Equal(r4DiffMTU) {
		t.Error("different MTU should be unequal")
	}
}

func TestRadvdDependencies(t *testing.T) {
	listenRef := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	r := Radvd{ListenIf: NetworkIf{IfName: "br0", ItemRef: listenRef}}
	deps := r.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem != listenRef {
		t.Errorf("dep should be ListenIf")
	}
	if deps[0].MustSatisfy != nil {
		t.Error("Radvd dep should not have MustSatisfy")
	}
}
