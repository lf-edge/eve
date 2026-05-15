// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"net"
	"testing"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

// --- Adapter ---

func TestAdapterName(t *testing.T) {
	a := Adapter{IfName: "eth0"}
	if got := a.Name(); got != "eth0" {
		t.Errorf("got %q, want %q", got, "eth0")
	}
}

func TestAdapterLabel(t *testing.T) {
	a := Adapter{LogicalLabel: "eth0"}
	if got := a.Label(); got != "eth0 (adapter)" {
		t.Errorf("got %q", got)
	}
}

func TestAdapterType(t *testing.T) {
	a := Adapter{}
	if got := a.Type(); got != genericitems.AdapterTypename {
		t.Errorf("got %q, want %q", got, genericitems.AdapterTypename)
	}
}

func TestAdapterExternal(t *testing.T) {
	a := Adapter{}
	if a.External() {
		t.Error("expected External() = false")
	}
}

func TestAdapterString(t *testing.T) {
	a := Adapter{IfName: "eth0", LogicalLabel: "eth0"}
	if s := a.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestAdapterGetMTU(t *testing.T) {
	a := Adapter{MTU: 0}
	if got := a.GetMTU(); got != types.DefaultMTU {
		t.Errorf("zero MTU: got %d, want %d", got, types.DefaultMTU)
	}
	a9k := Adapter{MTU: 9000}
	if got := a9k.GetMTU(); got != 9000 {
		t.Errorf("got %d, want 9000", got)
	}
}

func TestAdapterEqual(t *testing.T) {
	base := Adapter{
		IfName: "eth0", LogicalLabel: "eth0",
		L2Type: types.L2LinkTypeNone, WirelessType: types.WirelessTypeNone,
		DhcpType: types.DhcpTypeNOOP, MTU: 1500,
	}
	mod := func(f func(*Adapter)) Adapter {
		a := base
		f(&a)
		return a
	}
	tests := []struct {
		name  string
		other Adapter
		want  bool
	}{
		{"identical", base, true},
		{"diff L2Type", mod(func(a *Adapter) { a.L2Type = types.L2LinkTypeVLAN }), false},
		{"diff WirelessType", mod(func(a *Adapter) { a.WirelessType = types.WirelessTypeWifi }), false},
		{"diff UsedAsVlanParent", mod(func(a *Adapter) { a.UsedAsVlanParent = true }), false},
		{"diff DhcpType", mod(func(a *Adapter) { a.DhcpType = types.DhcpTypeStatic }), false},
		{"diff MTU", mod(func(a *Adapter) { a.MTU = 9000 }), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAdapterDependenciesPhysical(t *testing.T) {
	a := Adapter{IfName: "eth0", L2Type: types.L2LinkTypeNone}
	deps := a.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != genericitems.PhysIfTypename {
		t.Errorf("dep type: got %q, want %q", deps[0].RequiredItem.ItemType, genericitems.PhysIfTypename)
	}
	if deps[0].RequiredItem.ItemName != "eth0" {
		t.Errorf("dep name: got %q, want %q", deps[0].RequiredItem.ItemName, "eth0")
	}
	physIfOK := PhysIf{PhysIfName: "eth0", Usage: genericitems.IOUsageAdapter}
	physIfBond := PhysIf{PhysIfName: "eth0", Usage: genericitems.IOUsageBondAggrIf}
	if !deps[0].MustSatisfy(physIfOK) {
		t.Error("MustSatisfy: IOUsageAdapter should satisfy")
	}
	if deps[0].MustSatisfy(physIfBond) {
		t.Error("MustSatisfy: IOUsageBondAggrIf should not satisfy")
	}
}

func TestAdapterDependenciesVLAN(t *testing.T) {
	a := Adapter{IfName: "vlan10", L2Type: types.L2LinkTypeVLAN}
	deps := a.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != genericitems.VlanTypename {
		t.Errorf("dep type: got %q, want %q", deps[0].RequiredItem.ItemType, genericitems.VlanTypename)
	}
}

func TestAdapterDependenciesBond(t *testing.T) {
	a := Adapter{IfName: "bond0", L2Type: types.L2LinkTypeBond}
	deps := a.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != genericitems.BondTypename {
		t.Errorf("dep type: got %q, want %q", deps[0].RequiredItem.ItemType, genericitems.BondTypename)
	}
}

func TestAdapterDependenciesWifi(t *testing.T) {
	a := Adapter{IfName: "wlan0", L2Type: types.L2LinkTypeNone, WirelessType: types.WirelessTypeWifi}
	deps := a.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("WiFi: expected 2 deps, got %d", len(deps))
	}
	if deps[1].RequiredItem.ItemType != RFKillTypename {
		t.Errorf("WiFi rfkill dep type: got %q, want %q", deps[1].RequiredItem.ItemType, RFKillTypename)
	}
	if !deps[1].MustSatisfy(RFKill{EnableWlanRF: true}) {
		t.Error("MustSatisfy: enabled RF should satisfy")
	}
	if deps[1].MustSatisfy(RFKill{EnableWlanRF: false}) {
		t.Error("MustSatisfy: disabled RF should not satisfy")
	}
}

// --- Arp ---

func TestArpName(t *testing.T) {
	a := Arp{AdapterIfName: "eth0", IPAddr: net.ParseIP("192.168.1.1")}
	if got := a.Name(); got != "eth0/192.168.1.1" {
		t.Errorf("got %q, want %q", got, "eth0/192.168.1.1")
	}
}

func TestArpLabel(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	a := Arp{AdapterLL: "eth0", IPAddr: net.ParseIP("192.168.1.1"), HwAddr: mac}
	if s := a.Label(); s == "" {
		t.Error("expected non-empty label")
	}
}

func TestArpType(t *testing.T) {
	a := Arp{}
	if got := a.Type(); got != genericitems.ArpTypename {
		t.Errorf("got %q, want %q", got, genericitems.ArpTypename)
	}
}

func TestArpExternal(t *testing.T) {
	a := Arp{}
	if a.External() {
		t.Error("expected External() = false")
	}
}

func TestArpString(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	a := Arp{AdapterLL: "eth0", IPAddr: net.ParseIP("10.0.0.1"), HwAddr: mac}
	if s := a.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestArpEqual(t *testing.T) {
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	mac2, _ := net.ParseMAC("11:22:33:44:55:66")
	a1 := Arp{HwAddr: mac1}
	a2 := Arp{HwAddr: mac1}
	a3 := Arp{HwAddr: mac2}
	if !a1.Equal(a2) {
		t.Error("same MACs should be equal")
	}
	if a1.Equal(a3) {
		t.Error("different MACs should not be equal")
	}
}

func TestArpDependencies(t *testing.T) {
	a := Arp{AdapterIfName: "eth0", IPAddr: net.ParseIP("10.0.0.1")}
	deps := a.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != genericitems.AdapterTypename {
		t.Errorf("dep[0] type: got %q", deps[0].RequiredItem.ItemType)
	}
	if deps[1].RequiredItem.ItemType != genericitems.AdapterAddrsTypename {
		t.Errorf("dep[1] type: got %q", deps[1].RequiredItem.ItemType)
	}
	_, net1, _ := net.ParseCIDR("10.0.0.1/24")
	addrsWithIP := genericitems.AdapterAddrs{IPAddrs: []*net.IPNet{net1}}
	addrsEmpty := genericitems.AdapterAddrs{}
	if !deps[1].MustSatisfy(addrsWithIP) {
		t.Error("MustSatisfy: addrs with IPs should satisfy")
	}
	if deps[1].MustSatisfy(addrsEmpty) {
		t.Error("MustSatisfy: empty addrs should not satisfy")
	}
}

// --- IPRule ---

func TestIPRuleName(t *testing.T) {
	r := IPRule{Priority: 100, Table: 254}
	if got := r.Name(); got != "100/all/all/254" {
		t.Errorf("nil src/dst: got %q", got)
	}
	_, src, _ := net.ParseCIDR("10.0.0.0/8")
	r2 := IPRule{Priority: 200, Table: 1, Src: src}
	if got := r2.Name(); got != "200/10.0.0.0/8/all/1" {
		t.Errorf("with src: got %q", got)
	}
}

func TestIPRuleLabel(t *testing.T) {
	r := IPRule{Priority: 100, Table: 254}
	if got := r.Label(); got != "100: from all to all lookup 254" {
		t.Errorf("got %q", got)
	}
}

func TestIPRuleType(t *testing.T) {
	r4 := IPRule{IPv6: false}
	if got := r4.Type(); got != IPv4RuleTypename {
		t.Errorf("IPv4: got %q", got)
	}
	r6 := IPRule{IPv6: true}
	if got := r6.Type(); got != IPv6RuleTypename {
		t.Errorf("IPv6: got %q", got)
	}
}

func TestIPRuleExternal(t *testing.T) {
	r := IPRule{}
	if r.External() {
		t.Error("expected External() = false")
	}
}

func TestIPRuleDependencies(t *testing.T) {
	r := IPRule{}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestIPRuleString(t *testing.T) {
	r4 := IPRule{Priority: 100, Table: 254, IPv6: false}
	if s := r4.String(); s == "" {
		t.Error("expected non-empty string")
	}
	r6 := IPRule{Priority: 100, Table: 254, IPv6: true}
	if s := r6.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestIPRuleEqual(t *testing.T) {
	_, src, _ := net.ParseCIDR("10.0.0.0/8")
	_, dst, _ := net.ParseCIDR("192.168.0.0/16")
	base := IPRule{Priority: 100, Table: 254, IPv6: false, Src: src, Dst: dst}
	mod := func(f func(*IPRule)) IPRule {
		r := base
		f(&r)
		return r
	}
	tests := []struct {
		name  string
		other dg.Item
		want  bool
	}{
		{"identical", base, true},
		{"diff priority", mod(func(r *IPRule) { r.Priority = 200 }), false},
		{"diff table", mod(func(r *IPRule) { r.Table = 100 }), false},
		{"diff IPv6", mod(func(r *IPRule) { r.IPv6 = true }), false},
		{"nil src", mod(func(r *IPRule) { r.Src = nil }), false},
		{"nil dst", mod(func(r *IPRule) { r.Dst = nil }), false},
		{"wrong type", RFKill{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIPRuleSrcDstToString(t *testing.T) {
	r := IPRule{}
	if got := r.srcToString(); got != matchAll {
		t.Errorf("nil src: got %q, want %q", got, matchAll)
	}
	if got := r.dstToString(); got != matchAll {
		t.Errorf("nil dst: got %q, want %q", got, matchAll)
	}
	_, src, _ := net.ParseCIDR("10.0.0.0/8")
	_, dst, _ := net.ParseCIDR("192.168.0.0/16")
	r2 := IPRule{Src: src, Dst: dst}
	if got := r2.srcToString(); got != "10.0.0.0/8" {
		t.Errorf("src: got %q, want %q", got, "10.0.0.0/8")
	}
	if got := r2.dstToString(); got != "192.168.0.0/16" {
		t.Errorf("dst: got %q, want %q", got, "192.168.0.0/16")
	}
}

// --- PhysIf ---

func TestPhysIfName(t *testing.T) {
	p := PhysIf{PhysIfName: "eth0"}
	if got := p.Name(); got != "eth0" {
		t.Errorf("got %q, want %q", got, "eth0")
	}
}

func TestPhysIfLabel(t *testing.T) {
	p := PhysIf{PhysIfLL: "eth0"}
	if got := p.Label(); got != "eth0 (interface)" {
		t.Errorf("got %q", got)
	}
}

func TestPhysIfType(t *testing.T) {
	p := PhysIf{}
	if got := p.Type(); got != genericitems.PhysIfTypename {
		t.Errorf("got %q, want %q", got, genericitems.PhysIfTypename)
	}
}

func TestPhysIfExternal(t *testing.T) {
	p := PhysIf{}
	if p.External() {
		t.Error("expected External() = false")
	}
}

func TestPhysIfString(t *testing.T) {
	p := PhysIf{PhysIfName: "eth0", PhysIfLL: "eth0"}
	if s := p.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestPhysIfGetMTU(t *testing.T) {
	p := PhysIf{MTU: 0}
	if got := p.GetMTU(); got != types.DefaultMTU {
		t.Errorf("zero MTU: got %d, want %d", got, types.DefaultMTU)
	}
	p9k := PhysIf{MTU: 9000}
	if got := p9k.GetMTU(); got != 9000 {
		t.Errorf("got %d, want 9000", got)
	}
}

func TestPhysIfEqual(t *testing.T) {
	base := PhysIf{
		PhysIfName: "eth0", PhysIfLL: "eth0",
		Usage: genericitems.IOUsageAdapter, MTU: 1500,
	}
	tests := []struct {
		name  string
		other dg.Item
		want  bool
	}{
		{"identical", base, true},
		{"diff usage", PhysIf{PhysIfName: "eth0", PhysIfLL: "eth0",
			Usage: genericitems.IOUsageBondAggrIf, MTU: 1500}, false},
		{"diff MTU", PhysIf{PhysIfName: "eth0", PhysIfLL: "eth0",
			Usage: genericitems.IOUsageAdapter, MTU: 9000}, false},
		{"diff master", PhysIf{PhysIfName: "eth0", PhysIfLL: "eth0",
			Usage: genericitems.IOUsageAdapter, MTU: 1500, MasterIfName: "bond0"}, false},
		{"wrong type", RFKill{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPhysIfDependencies(t *testing.T) {
	p := PhysIf{PhysIfName: "eth0"}
	deps := p.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != genericitems.NetIOTypename {
		t.Errorf("dep type: got %q, want %q", deps[0].RequiredItem.ItemType, genericitems.NetIOTypename)
	}
	if deps[0].RequiredItem.ItemName != "eth0" {
		t.Errorf("dep name: got %q, want %q", deps[0].RequiredItem.ItemName, "eth0")
	}
}

// --- RFKill ---

func TestRFKillName(t *testing.T) {
	r := RFKill{}
	if got := r.Name(); got != "rfkill" {
		t.Errorf("got %q, want %q", got, "rfkill")
	}
}

func TestRFKillLabel(t *testing.T) {
	r := RFKill{}
	if got := r.Label(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestRFKillType(t *testing.T) {
	r := RFKill{}
	if got := r.Type(); got != RFKillTypename {
		t.Errorf("got %q, want %q", got, RFKillTypename)
	}
}

func TestRFKillExternal(t *testing.T) {
	r := RFKill{}
	if r.External() {
		t.Error("expected External() = false")
	}
}

func TestRFKillString(t *testing.T) {
	r := RFKill{EnableWlanRF: true}
	if s := r.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestRFKillDependencies(t *testing.T) {
	r := RFKill{}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestRFKillEqual(t *testing.T) {
	r1 := RFKill{EnableWlanRF: true}
	r2 := RFKill{EnableWlanRF: true}
	r3 := RFKill{EnableWlanRF: false}
	if !r1.Equal(r2) {
		t.Error("same EnableWlanRF should be equal")
	}
	if r1.Equal(r3) {
		t.Error("different EnableWlanRF should not be equal")
	}
	if r1.Equal(Arp{}) {
		t.Error("wrong type should not be equal")
	}
}

// --- Route ---

func TestRouteName(t *testing.T) {
	r := Route{
		Route:         netlink.Route{Family: netlink.FAMILY_V4, Table: 254},
		AdapterIfName: "eth0",
	}
	if got := r.Name(); got != "254/eth0/default" {
		t.Errorf("nil Dst (default): got %q", got)
	}
	_, dst, _ := net.ParseCIDR("192.168.1.0/24")
	r2 := Route{
		Route:         netlink.Route{Family: netlink.FAMILY_V4, Table: 100, Dst: dst},
		AdapterIfName: "eth0",
	}
	if got := r2.Name(); got != "100/eth0/192.168.1.0/24" {
		t.Errorf("specific Dst: got %q", got)
	}
}

func TestRouteLabel(t *testing.T) {
	r := Route{
		Route:         netlink.Route{Family: netlink.FAMILY_V4, Table: 254},
		AdapterIfName: "eth0", AdapterLL: "eth0",
	}
	if s := r.Label(); s == "" {
		t.Error("expected non-empty label")
	}
}

func TestRouteType(t *testing.T) {
	r4 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4}}
	if got := r4.Type(); got != genericitems.IPv4RouteTypename {
		t.Errorf("IPv4: got %q", got)
	}
	r6 := Route{Route: netlink.Route{Family: netlink.FAMILY_V6}}
	if got := r6.Type(); got != genericitems.IPv6RouteTypename {
		t.Errorf("IPv6: got %q", got)
	}
	rBad := Route{Route: netlink.Route{Family: 99}}
	if got := rBad.Type(); got != genericitems.UnsupportedRouteTypename {
		t.Errorf("unsupported: got %q", got)
	}
}

func TestRouteExternal(t *testing.T) {
	r := Route{}
	if r.External() {
		t.Error("expected External() = false")
	}
}

func TestRouteString(t *testing.T) {
	r := Route{Route: netlink.Route{Family: netlink.FAMILY_V4}, AdapterLL: "eth0"}
	if s := r.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestRouteEqual(t *testing.T) {
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	gw := net.ParseIP("192.168.1.1")
	r1 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: dst, Gw: gw}}
	r2 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: dst, Gw: gw}}
	r3DiffGW := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: dst}}
	if !r1.Equal(r2) {
		t.Error("identical routes should be equal")
	}
	if r1.Equal(r3DiffGW) {
		t.Error("different GW should not be equal")
	}
	if r1.Equal(Arp{}) {
		t.Error("wrong type should not be equal")
	}
}

func TestRouteIPVersionStr(t *testing.T) {
	r4 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4}}
	if got := r4.ipVersionStr(); got != "IPv4" {
		t.Errorf("got %q, want %q", got, "IPv4")
	}
	r6 := Route{Route: netlink.Route{Family: netlink.FAMILY_V6}}
	if got := r6.ipVersionStr(); got != "IPv6" {
		t.Errorf("got %q, want %q", got, "IPv6")
	}
	rBad := Route{Route: netlink.Route{Family: 99}}
	if s := rBad.ipVersionStr(); s == "" {
		t.Error("expected non-empty string for unsupported family")
	}
}

func TestRouteHasDefaultDst(t *testing.T) {
	rNil := Route{Route: netlink.Route{Dst: nil}}
	if !rNil.hasDefaultDst() {
		t.Error("nil Dst should be default")
	}
	_, anyV4, _ := net.ParseCIDR("0.0.0.0/0")
	rAnyV4 := Route{Route: netlink.Route{Dst: anyV4}}
	if !rAnyV4.hasDefaultDst() {
		t.Error("0.0.0.0/0 should be default")
	}
	_, anyV6, _ := net.ParseCIDR("::/0")
	rAnyV6 := Route{Route: netlink.Route{Dst: anyV6}}
	if !rAnyV6.hasDefaultDst() {
		t.Error("::/0 should be default")
	}
	_, specific, _ := net.ParseCIDR("192.168.0.0/16")
	rSpecific := Route{Route: netlink.Route{Dst: specific}}
	if rSpecific.hasDefaultDst() {
		t.Error("192.168.0.0/16 should not be default")
	}
}

func TestRouteNormalizedNetlinkRoute(t *testing.T) {
	// nil Dst with FAMILY_V4 → 0.0.0.0/0, Flags cleared
	r4 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Dst: nil, Flags: 0x10}}
	norm4 := r4.normalizedNetlinkRoute()
	if norm4.Dst == nil {
		t.Fatal("normalized IPv4 Dst should not be nil")
	}
	if !norm4.Dst.IP.IsUnspecified() {
		t.Errorf("normalized IPv4 Dst IP should be unspecified, got %v", norm4.Dst.IP)
	}
	ones4, _ := norm4.Dst.Mask.Size()
	if ones4 != 0 {
		t.Errorf("normalized IPv4 Dst prefix length should be 0, got %d", ones4)
	}
	if norm4.Flags != 0 {
		t.Errorf("normalized route should have Flags=0, got %d", norm4.Flags)
	}

	// nil Dst with FAMILY_V6 → ::/0
	r6 := Route{Route: netlink.Route{Family: netlink.FAMILY_V6, Dst: nil}}
	norm6 := r6.normalizedNetlinkRoute()
	if norm6.Dst == nil {
		t.Fatal("normalized IPv6 Dst should not be nil")
	}
	ones6, _ := norm6.Dst.Mask.Size()
	if ones6 != 0 {
		t.Errorf("normalized IPv6 Dst prefix length should be 0, got %d", ones6)
	}

	// non-nil Dst is preserved
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	rDst := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Dst: dst}}
	normDst := rDst.normalizedNetlinkRoute()
	if normDst.Dst.String() != "10.0.0.0/8" {
		t.Errorf("specific Dst should be preserved, got %v", normDst.Dst)
	}
}

func TestRouteDependencies(t *testing.T) {
	gw := net.ParseIP("192.168.1.254")
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	_, otherSubnet, _ := net.ParseCIDR("10.0.0.0/8")
	r := Route{
		Route:         netlink.Route{Family: netlink.FAMILY_V4, Gw: gw},
		AdapterIfName: "eth0",
	}
	deps := r.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != genericitems.AdapterTypename {
		t.Errorf("dep[0] type: got %q", deps[0].RequiredItem.ItemType)
	}
	if deps[1].RequiredItem.ItemType != genericitems.AdapterAddrsTypename {
		t.Errorf("dep[1] type: got %q", deps[1].RequiredItem.ItemType)
	}
	addrsMatch := genericitems.AdapterAddrs{IPAddrs: []*net.IPNet{subnet}}
	addrsNoMatch := genericitems.AdapterAddrs{IPAddrs: []*net.IPNet{otherSubnet}}
	addrsEmpty := genericitems.AdapterAddrs{}
	if !deps[1].MustSatisfy(addrsMatch) {
		t.Error("matching subnet should satisfy")
	}
	if deps[1].MustSatisfy(addrsNoMatch) {
		t.Error("non-matching subnet should not satisfy")
	}
	if deps[1].MustSatisfy(addrsEmpty) {
		t.Error("empty addrs should not satisfy")
	}
}
