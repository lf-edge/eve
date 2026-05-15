// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"net"
	"testing"

	dg "github.com/lf-edge/eve-libs/depgraph"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
)

func mustParseCIDRLI(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

func boolPtr(b bool) *bool { return &b }

func uint8Ptr(v uint8) *uint8 { return &v }

func uint32Ptr(v uint32) *uint32 { return &v }

// --- equalBoolPtr ---

func TestEqualBoolPtr(t *testing.T) {
	tr := true
	fa := false
	if !equalBoolPtr(nil, nil) {
		t.Error("(nil, nil) should be equal")
	}
	if equalBoolPtr(nil, &tr) {
		t.Error("(nil, true) should be unequal")
	}
	if equalBoolPtr(&tr, nil) {
		t.Error("(true, nil) should be unequal")
	}
	if !equalBoolPtr(&tr, &tr) {
		t.Error("(true, true) should be equal")
	}
	if equalBoolPtr(&tr, &fa) {
		t.Error("(true, false) should be unequal")
	}
}

func TestBoolPtrToString(t *testing.T) {
	if got := boolPtrToString(nil); got != "undefined" {
		t.Errorf("nil: got %q", got)
	}
	if got := boolPtrToString(boolPtr(true)); got != "true" {
		t.Errorf("true: got %q", got)
	}
	if got := boolPtrToString(boolPtr(false)); got != "false" {
		t.Errorf("false: got %q", got)
	}
}

func TestBoolToDigitString(t *testing.T) {
	if got := boolToDigitString(true); got != "1" {
		t.Errorf("true: got %q", got)
	}
	if got := boolToDigitString(false); got != "0" {
		t.Errorf("false: got %q", got)
	}
}

// --- equalUint8Ptr ---

func TestEqualUint8Ptr(t *testing.T) {
	v6 := uint8(6)
	v17 := uint8(17)
	if !equalUint8Ptr(nil, nil) {
		t.Error("(nil, nil) should be equal")
	}
	if equalUint8Ptr(nil, &v6) {
		t.Error("(nil, 6) should be unequal")
	}
	if !equalUint8Ptr(&v6, &v6) {
		t.Error("(6, 6) should be equal")
	}
	if equalUint8Ptr(&v6, &v17) {
		t.Error("(6, 17) should be unequal")
	}
}

// --- BridgePortName ---

func TestBridgePortName(t *testing.T) {
	if got := BridgePortName("br0", "eth0"); got != "br0/eth0" {
		t.Errorf("got %q, want %q", got, "br0/eth0")
	}
}

// --- TCMatchProtocol.String ---

func TestTCMatchProtocolString(t *testing.T) {
	tests := []struct {
		p    TCMatchProtocol
		want string
	}{
		{TCMatchProtoUndefined, "all"},
		{TCMatchProtoIPv4, "ip"},
		{TCMatchProtoIPv6, "ipv6"},
		{TCMatchProtoARP, "arp"},
	}
	for _, tc := range tests {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("Protocol(%d).String() = %q, want %q", tc.p, got, tc.want)
		}
	}
}

// --- BPDUGuard ---

func TestBPDUGuardName(t *testing.T) {
	g := BPDUGuard{PortIfName: "eth0"}
	if got := g.Name(); got != "eth0" {
		t.Errorf("got %q, want %q", got, "eth0")
	}
}

func TestBPDUGuardLabel(t *testing.T) {
	g := BPDUGuard{PortIfName: "eth0"}
	if got := g.Label(); got != "eth0 (BPDU guard)" {
		t.Errorf("got %q", got)
	}
}

func TestBPDUGuardType(t *testing.T) {
	g := BPDUGuard{}
	if got := g.Type(); got != BPDUGuardTypename {
		t.Errorf("got %q, want %q", got, BPDUGuardTypename)
	}
}

func TestBPDUGuardExternal(t *testing.T) {
	g := BPDUGuard{}
	if g.External() {
		t.Error("expected External() = false")
	}
}

func TestBPDUGuardString(t *testing.T) {
	g := BPDUGuard{BridgeIfName: "br0", PortIfName: "eth0", ForVIF: true}
	if s := g.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestBPDUGuardEqual(t *testing.T) {
	g1 := BPDUGuard{BridgeIfName: "br0", PortIfName: "eth0", ForVIF: false}
	g2Same := BPDUGuard{BridgeIfName: "br0", PortIfName: "vif0", ForVIF: false} // PortIfName not compared
	g3DiffBridge := BPDUGuard{BridgeIfName: "br1", PortIfName: "eth0", ForVIF: false}
	g4DiffForVIF := BPDUGuard{BridgeIfName: "br0", PortIfName: "eth0", ForVIF: true}
	if !g1.Equal(g2Same) {
		t.Error("same BridgeIfName+ForVIF should be equal (PortIfName not compared)")
	}
	if g1.Equal(g3DiffBridge) {
		t.Error("different BridgeIfName should be unequal")
	}
	if g1.Equal(g4DiffForVIF) {
		t.Error("different ForVIF should be unequal")
	}
	if g1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestBPDUGuardDependencies(t *testing.T) {
	g := BPDUGuard{BridgeIfName: "br0", PortIfName: "eth0"}
	deps := g.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != BridgeTypename {
		t.Errorf("first dep should be Bridge, got %q", deps[0].RequiredItem.ItemType)
	}
	if deps[1].RequiredItem.ItemType != BridgePortTypename {
		t.Errorf("second dep should be BridgePort, got %q", deps[1].RequiredItem.ItemType)
	}
	wantBPName := BridgePortName("br0", "eth0")
	if deps[1].RequiredItem.ItemName != wantBPName {
		t.Errorf("BridgePort dep name: got %q, want %q", deps[1].RequiredItem.ItemName, wantBPName)
	}
}

// --- BridgeFwdMask ---

func TestBridgeFwdMaskName(t *testing.T) {
	m := BridgeFwdMask{BridgeIfName: "br0"}
	if got := m.Name(); got != "br0" {
		t.Errorf("got %q", got)
	}
}

func TestBridgeFwdMaskLabel(t *testing.T) {
	m := BridgeFwdMask{BridgeIfName: "br0"}
	if got := m.Label(); got != "br0 (Forwarding mask)" {
		t.Errorf("got %q", got)
	}
}

func TestBridgeFwdMaskType(t *testing.T) {
	m := BridgeFwdMask{}
	if got := m.Type(); got != BridgeFwdMaskTypename {
		t.Errorf("got %q, want %q", got, BridgeFwdMaskTypename)
	}
}

func TestBridgeFwdMaskExternal(t *testing.T) {
	m := BridgeFwdMask{}
	if m.External() {
		t.Error("expected External() = false")
	}
}

func TestBridgeFwdMaskString(t *testing.T) {
	m := BridgeFwdMask{BridgeIfName: "br0", ForwardLLDP: true}
	if s := m.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestBridgeFwdMaskEqual(t *testing.T) {
	m1 := BridgeFwdMask{BridgeIfName: "br0", ForwardLLDP: true}
	m2Same := BridgeFwdMask{BridgeIfName: "br0", ForwardLLDP: true}
	m3Diff := BridgeFwdMask{BridgeIfName: "br0", ForwardLLDP: false}
	if !m1.Equal(m2Same) {
		t.Error("identical masks should be equal")
	}
	if m1.Equal(m3Diff) {
		t.Error("different ForwardLLDP should be unequal")
	}
	if m1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestBridgeFwdMaskDependencies(t *testing.T) {
	m := BridgeFwdMask{BridgeIfName: "br0"}
	deps := m.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != BridgeTypename || deps[0].RequiredItem.ItemName != "br0" {
		t.Errorf("dep should be Bridge br0, got %+v", deps[0].RequiredItem)
	}
}

func TestToMaskValue(t *testing.T) {
	tests := []struct {
		m    BridgeFwdMask
		want string
	}{
		{BridgeFwdMask{}, "0x0"},
		{BridgeFwdMask{ForwardLLDP: true}, "0x4000"},
		{BridgeFwdMask{ForwardEAPOL: true}, "0x8"},
		{BridgeFwdMask{ForwardMVRP: true}, "0x2000"},
		{BridgeFwdMask{ForwardLLDP: true, ForwardEAPOL: true}, "0x4008"},
	}
	for _, tc := range tests {
		if got := tc.m.toMaskValue(); got != tc.want {
			t.Errorf("toMaskValue(%+v): got %q, want %q", tc.m, got, tc.want)
		}
	}
}

// --- Bridge ---

func TestBridgeName(t *testing.T) {
	b := Bridge{IfName: "br0"}
	if got := b.Name(); got != "br0" {
		t.Errorf("got %q", got)
	}
}

func TestBridgeLabel(t *testing.T) {
	b := Bridge{IfName: "br0"}
	if got := b.Label(); got != "br0 (bridge)" {
		t.Errorf("got %q", got)
	}
}

func TestBridgeType(t *testing.T) {
	b := Bridge{}
	if got := b.Type(); got != BridgeTypename {
		t.Errorf("got %q, want %q", got, BridgeTypename)
	}
}

func TestBridgeExternalCreatedByNIM(t *testing.T) {
	b1 := Bridge{CreatedByNIM: true}
	b2 := Bridge{CreatedByNIM: false}
	if !b1.External() {
		t.Error("CreatedByNIM=true should be external")
	}
	if b2.External() {
		t.Error("CreatedByNIM=false should not be external")
	}
}

func TestBridgeString(t *testing.T) {
	b := Bridge{IfName: "br0", MTU: 1500}
	if s := b.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestBridgeEqual(t *testing.T) {
	mac1 := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	mac2 := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	b1 := Bridge{IfName: "br0", MACAddress: mac1, MTU: 1500}
	b2Same := Bridge{IfName: "br0", MACAddress: mac1, MTU: 1500}
	b3DiffMAC := Bridge{IfName: "br0", MACAddress: mac2, MTU: 1500}
	b4DiffMTU := Bridge{IfName: "br0", MACAddress: mac1, MTU: 9000}
	if !b1.Equal(b2Same) {
		t.Error("identical bridges should be equal")
	}
	if b1.Equal(b3DiffMAC) {
		t.Error("different MAC should be unequal")
	}
	if b1.Equal(b4DiffMTU) {
		t.Error("different MTU should be unequal")
	}
	if b1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestBridgeGetAssignedIPs(t *testing.T) {
	ip := &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}
	b := Bridge{IPAddresses: []*net.IPNet{ip}}
	if got := b.GetAssignedIPs(); len(got) != 1 {
		t.Errorf("expected 1 IP, got %d", len(got))
	}
}

func TestBridgeGetMTU(t *testing.T) {
	b0 := Bridge{MTU: 0}
	if got := b0.GetMTU(); got != types.DefaultMTU {
		t.Errorf("zero MTU: got %d, want DefaultMTU (%d)", got, types.DefaultMTU)
	}
	b9000 := Bridge{MTU: 9000}
	if got := b9000.GetMTU(); got != 9000 {
		t.Errorf("explicit MTU: got %d, want 9000", got)
	}
}

func TestBridgeDependenciesExternal(t *testing.T) {
	b := Bridge{CreatedByNIM: true}
	if deps := b.Dependencies(); deps != nil {
		t.Errorf("external bridge should have no deps, got %v", deps)
	}
}

func TestBridgeDependenciesNonExternal(t *testing.T) {
	ip1 := &net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}
	ip2 := &net.IPNet{IP: net.IP{10, 0, 1, 1}, Mask: net.CIDRMask(24, 32)}
	b := Bridge{IfName: "br0", IPAddresses: []*net.IPNet{ip1, ip2}}
	deps := b.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps (one per IP), got %d", len(deps))
	}
	// MustSatisfy: IPReserve with matching NetIf → true
	for i, dep := range deps {
		if dep.MustSatisfy == nil {
			t.Errorf("dep[%d] should have MustSatisfy", i)
			continue
		}
		matchingReserve := generic.IPReserve{
			AddrWithMask: b.IPAddresses[i],
			NetIf:        generic.NetworkIf{ItemRef: dg.Reference(b)},
		}
		if !dep.MustSatisfy(matchingReserve) {
			t.Errorf("dep[%d] MustSatisfy should return true for matching IPReserve", i)
		}
		nonMatchingReserve := generic.IPReserve{
			AddrWithMask: b.IPAddresses[i],
			NetIf:        generic.NetworkIf{ItemRef: dg.ItemRef{ItemType: "Bridge", ItemName: "other"}},
		}
		if dep.MustSatisfy(nonMatchingReserve) {
			t.Errorf("dep[%d] MustSatisfy should return false for non-matching NetIf", i)
		}
	}
}

// --- BridgePort ---

func TestBridgePortItemName(t *testing.T) {
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}}
	if got := p.Name(); got != "br0/eth0" {
		t.Errorf("got %q, want %q", got, "br0/eth0")
	}
}

func TestBridgePortLabel(t *testing.T) {
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}}
	if got := p.Label(); got != "add port eth0 into bridge br0" {
		t.Errorf("got %q", got)
	}
}

func TestBridgePortType(t *testing.T) {
	p := BridgePort{}
	if got := p.Type(); got != BridgePortTypename {
		t.Errorf("got %q, want %q", got, BridgePortTypename)
	}
}

func TestBridgePortExternal(t *testing.T) {
	p := BridgePort{}
	if p.External() {
		t.Error("expected External() = false")
	}
}

func TestBridgePortString(t *testing.T) {
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}}
	if s := p.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestBridgePortEqual(t *testing.T) {
	p1 := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}, MTU: 1500}
	p2Same := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}, MTU: 1500}
	p3DiffBridge := BridgePort{BridgeIfName: "br1", Variant: BridgePortVariant{PortIfName: "eth0"}, MTU: 1500}
	if !p1.Equal(p2Same) {
		t.Error("identical BridgePorts should be equal")
	}
	if p1.Equal(p3DiffBridge) {
		t.Error("different BridgeIfName should be unequal")
	}
	if p1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestBridgePortGetMTU(t *testing.T) {
	p0 := BridgePort{MTU: 0}
	if got := p0.GetMTU(); got != types.DefaultMTU {
		t.Errorf("zero MTU: got %d", got)
	}
	p9000 := BridgePort{MTU: 9000}
	if got := p9000.GetMTU(); got != 9000 {
		t.Errorf("explicit MTU: got %d", got)
	}
}

func TestBridgePortDependenciesVIF(t *testing.T) {
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{VIFIfName: "vif0"}}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != BridgeTypename {
		t.Errorf("first dep should be Bridge")
	}
	if deps[1].RequiredItem.ItemType != VIFTypename || deps[1].RequiredItem.ItemName != "vif0" {
		t.Errorf("second dep should be VIF vif0, got %+v", deps[1].RequiredItem)
	}
}

func TestBridgePortDependenciesPort(t *testing.T) {
	// ExternallyBridged=false: no MustSatisfy
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[1].RequiredItem.ItemType != generic.PortTypename {
		t.Errorf("second dep should be Port")
	}
	if deps[1].MustSatisfy != nil {
		t.Error("non-externally bridged port dep should not have MustSatisfy")
	}
}

func TestBridgePortDependenciesPortExternallyBridged(t *testing.T) {
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}, ExternallyBridged: true}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[1].MustSatisfy == nil {
		t.Error("externally bridged port dep should have MustSatisfy")
	}
	// Port with matching MasterIfName → true
	portMatch := generic.Port{MasterIfName: "br0"}
	if !deps[1].MustSatisfy(portMatch) {
		t.Error("MustSatisfy should be true for matching MasterIfName")
	}
	portNoMatch := generic.Port{MasterIfName: "br1"}
	if deps[1].MustSatisfy(portNoMatch) {
		t.Error("MustSatisfy should be false for non-matching MasterIfName")
	}
}

func TestBridgePortDependenciesVLANSubinterface(t *testing.T) {
	subIf := &VLANSubinterface{IfName: "eth0.100", VID: 100}
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{VLANSubinterface: subIf}, ExternallyBridged: true}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[1].RequiredItem.ItemType != VLANSubIntfTypename {
		t.Errorf("second dep should be VLANSubinterface, got %q", deps[1].RequiredItem.ItemType)
	}
	if deps[1].MustSatisfy == nil {
		t.Error("VLANSubinterface dep should have MustSatisfy")
	}
	// VLANSubIf with matching ParentIfName and ID → true
	match := VLANSubIf{ParentIfName: "br0", ID: 100}
	if !deps[1].MustSatisfy(match) {
		t.Error("MustSatisfy should be true for matching VLANSubIf")
	}
	noMatch := VLANSubIf{ParentIfName: "br0", ID: 200}
	if deps[1].MustSatisfy(noMatch) {
		t.Error("MustSatisfy should be false for wrong VID")
	}
}

// --- DummyIf ---

func TestDummyIfName(t *testing.T) {
	d := DummyIf{IfName: "dummy0"}
	if got := d.Name(); got != "dummy0" {
		t.Errorf("got %q", got)
	}
}

func TestDummyIfLabel(t *testing.T) {
	d := DummyIf{IfName: "dummy0"}
	if got := d.Label(); got != "" {
		t.Errorf("expected empty label, got %q", got)
	}
}

func TestDummyIfType(t *testing.T) {
	d := DummyIf{}
	if got := d.Type(); got != DummyIfTypename {
		t.Errorf("got %q, want %q", got, DummyIfTypename)
	}
}

func TestDummyIfExternal(t *testing.T) {
	d := DummyIf{}
	if d.External() {
		t.Error("expected External() = false")
	}
}

func TestDummyIfString(t *testing.T) {
	d := DummyIf{IfName: "dummy0", ARPOff: true}
	if s := d.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestDummyIfEqual(t *testing.T) {
	d1 := DummyIf{IfName: "dummy0", ARPOff: true}
	d2Same := DummyIf{IfName: "dummy0", ARPOff: true}
	d3Diff := DummyIf{IfName: "dummy0", ARPOff: false}
	if !d1.Equal(d2Same) {
		t.Error("identical DummyIf instances should be equal")
	}
	if d1.Equal(d3Diff) {
		t.Error("different ARPOff should be unequal")
	}
	if d1.Equal(Bridge{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestDummyIfDependencies(t *testing.T) {
	d := DummyIf{}
	if deps := d.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

// --- IPRule (nireconciler version) ---

func TestIPRuleName(t *testing.T) {
	// No mark
	r := IPRule{Priority: 100, Table: 254, Src: mustParseCIDRLI("10.0.0.0/24")}
	want := "100/10.0.0.0/24/all/254"
	if got := r.Name(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// With mark
	mask := uint32(0xff)
	r2 := IPRule{Priority: 200, Table: 100, Mark: 0xab, Mask: &mask}
	want2 := "200/all/all/ab/ff/100"
	if got := r2.Name(); got != want2 {
		t.Errorf("with mark: got %q, want %q", got, want2)
	}
	// Mark set but no Mask → no-mark format
	r3 := IPRule{Priority: 100, Table: 254, Mark: 5}
	want3 := "100/all/all/254"
	if got := r3.Name(); got != want3 {
		t.Errorf("mark without mask: got %q, want %q", got, want3)
	}
}

func TestIPRuleLabel(t *testing.T) {
	r := IPRule{Priority: 100, Table: 254}
	got := r.Label()
	if got == "" {
		t.Error("expected non-empty label")
	}
	// With mark
	mask := uint32(0xff)
	r2 := IPRule{Priority: 100, Table: 254, Mark: 0xab, Mask: &mask}
	if got2 := r2.Label(); got2 == got {
		t.Error("label with mark should differ from label without mark")
	}
}

func TestIPRuleType(t *testing.T) {
	r := IPRule{}
	if got := r.Type(); got != IPRuleTypename {
		t.Errorf("got %q, want %q", got, IPRuleTypename)
	}
}

func TestIPRuleExternal(t *testing.T) {
	r := IPRule{}
	if r.External() {
		t.Error("expected External() = false")
	}
}

func TestIPRuleString(t *testing.T) {
	r := IPRule{Priority: 100, Table: 254}
	if s := r.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestIPRuleDependencies(t *testing.T) {
	r := IPRule{}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestIPRuleSrcDstToString(t *testing.T) {
	r := IPRule{}
	if got := r.srcToString(); got != "all" {
		t.Errorf("nil src: got %q", got)
	}
	if got := r.dstToString(); got != "all" {
		t.Errorf("nil dst: got %q", got)
	}
	r2 := IPRule{Src: mustParseCIDRLI("10.0.0.0/24"), Dst: mustParseCIDRLI("192.168.0.0/16")}
	if got := r2.srcToString(); got != "10.0.0.0/24" {
		t.Errorf("src: got %q", got)
	}
	if got := r2.dstToString(); got != "192.168.0.0/16" {
		t.Errorf("dst: got %q", got)
	}
}

func TestIPRuleEqual(t *testing.T) {
	mask := uint32(0xff)
	r1 := IPRule{Priority: 100, Table: 254, Mark: 0xab, Mask: &mask}
	r2Same := IPRule{Priority: 100, Table: 254, Mark: 0xab, Mask: &mask}
	r3DiffMask := IPRule{Priority: 100, Table: 254, Mark: 0xab, Mask: uint32Ptr(0xfe)}
	r4OneMaskNil := IPRule{Priority: 100, Table: 254, Mark: 0xab}
	r5BothNil := IPRule{Priority: 100, Table: 254}
	r6BothNil := IPRule{Priority: 100, Table: 254}
	if !r1.Equal(r2Same) {
		t.Error("identical rules should be equal")
	}
	if r1.Equal(r3DiffMask) {
		t.Error("different Mask value should be unequal")
	}
	if r1.Equal(r4OneMaskNil) {
		t.Error("one nil Mask should be unequal")
	}
	if !r5BothNil.Equal(r6BothNil) {
		t.Error("both nil Mask should be equal")
	}
	if r1.Equal(Bridge{}) {
		t.Error("wrong type should be unequal")
	}
}

// --- IPSet ---

func TestIPSetName(t *testing.T) {
	s := IPSet{SetName: "my-set"}
	if got := s.Name(); got != "my-set" {
		t.Errorf("got %q", got)
	}
}

func TestIPSetLabel(t *testing.T) {
	s := IPSet{}
	if got := s.Label(); got != "" {
		t.Errorf("expected empty label, got %q", got)
	}
}

func TestIPSetType(t *testing.T) {
	s := IPSet{}
	if got := s.Type(); got != generic.IPSetTypename {
		t.Errorf("got %q, want %q", got, generic.IPSetTypename)
	}
}

func TestIPSetExternal(t *testing.T) {
	s := IPSet{}
	if s.External() {
		t.Error("expected External() = false")
	}
}

func TestIPSetString(t *testing.T) {
	s := IPSet{SetName: "my-set", TypeName: "hash:ip"}
	if str := s.String(); str == "" {
		t.Error("expected non-empty string")
	}
}

func TestIPSetDependencies(t *testing.T) {
	s := IPSet{}
	if deps := s.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestIPSetEqual(t *testing.T) {
	s1 := IPSet{SetName: "s", TypeName: "hash:ip", Entries: []string{"10.0.0.1", "10.0.0.2"}}
	s2Same := IPSet{SetName: "s", TypeName: "hash:ip", Entries: []string{"10.0.0.2", "10.0.0.1"}} // order-independent
	s3DiffEntry := IPSet{SetName: "s", TypeName: "hash:ip", Entries: []string{"10.0.0.1"}}
	if !s1.Equal(s2Same) {
		t.Error("set equality should be order-independent")
	}
	if s1.Equal(s3DiffEntry) {
		t.Error("different entries should be unequal")
	}
	if s1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

// --- Sysctl ---

func TestSysctlName(t *testing.T) {
	// Host, no interface
	s1 := Sysctl{}
	if got := s1.Name(); got != "sysctl-host" {
		t.Errorf("host no-if: got %q", got)
	}
	// Host with interface
	s2 := Sysctl{NetIf: generic.NetworkIf{IfName: "br0"}}
	if got := s2.Name(); got != "sysctl-host-br0" {
		t.Errorf("host with-if: got %q", got)
	}
	// App, no interface
	appID := uuid.UUID{1}
	s3 := Sysctl{ForApp: ContainerApp{ID: appID}}
	if got := s3.Name(); got != "sysctl-"+appID.String() {
		t.Errorf("app no-if: got %q", got)
	}
	// App with interface
	s4 := Sysctl{ForApp: ContainerApp{ID: appID}, NetIf: generic.NetworkIf{IfName: "vif0"}}
	if got := s4.Name(); got != "sysctl-"+appID.String()+"-vif0" {
		t.Errorf("app with-if: got %q", got)
	}
}

func TestSysctlLabel(t *testing.T) {
	s := Sysctl{}
	if got := s.Label(); got != "" {
		t.Errorf("expected empty label, got %q", got)
	}
}

func TestSysctlType(t *testing.T) {
	s := Sysctl{}
	if got := s.Type(); got != SysctlTypename {
		t.Errorf("got %q, want %q", got, SysctlTypename)
	}
}

func TestSysctlExternal(t *testing.T) {
	s := Sysctl{}
	if s.External() {
		t.Error("expected External() = false")
	}
}

func TestSysctlString(t *testing.T) {
	s := Sysctl{EnableDAD: boolPtr(false)}
	if str := s.String(); str == "" {
		t.Error("expected non-empty string")
	}
}

func TestSysctlEqual(t *testing.T) {
	tr := true
	fa := false
	s1 := Sysctl{EnableDAD: &tr, EnableARPNotify: &fa}
	s2Same := Sysctl{EnableDAD: &tr, EnableARPNotify: &fa}
	s3Diff := Sysctl{EnableDAD: &fa, EnableARPNotify: &fa}
	if !s1.Equal(s2Same) {
		t.Error("identical Sysctl instances should be equal")
	}
	if s1.Equal(s3Diff) {
		t.Error("different EnableDAD should be unequal")
	}
	if s1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestSysctlDependencies(t *testing.T) {
	// No interface → no deps
	s1 := Sysctl{}
	if deps := s1.Dependencies(); len(deps) != 0 {
		t.Errorf("no interface: expected 0 deps, got %d", len(deps))
	}
	// With interface → 1 dep
	ref := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	s2 := Sysctl{NetIf: generic.NetworkIf{IfName: "br0", ItemRef: ref}}
	deps := s2.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("with interface: expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem != ref {
		t.Errorf("dep should reference NetIf")
	}
}

// --- TCIngress ---

func TestTCIngressName(t *testing.T) {
	tc := TCIngress{NetIf: generic.NetworkIf{IfName: "eth0"}}
	if got := tc.Name(); got != "eth0" {
		t.Errorf("got %q", got)
	}
}

func TestTCIngressLabel(t *testing.T) {
	tc := TCIngress{NetIf: generic.NetworkIf{IfName: "eth0"}}
	if got := tc.Label(); got != "TC-Ingress for eth0" {
		t.Errorf("got %q", got)
	}
}

func TestTCIngressType(t *testing.T) {
	tc := TCIngress{}
	if got := tc.Type(); got != TCIngressTypename {
		t.Errorf("got %q, want %q", got, TCIngressTypename)
	}
}

func TestTCIngressExternal(t *testing.T) {
	tc := TCIngress{}
	if tc.External() {
		t.Error("expected External() = false")
	}
}

func TestTCIngressString(t *testing.T) {
	tc := TCIngress{NetIf: generic.NetworkIf{IfName: "eth0"}}
	if s := tc.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestTCIngressEqual(t *testing.T) {
	ref := dg.ItemRef{ItemType: "Port", ItemName: "eth0"}
	tc1 := TCIngress{NetIf: generic.NetworkIf{IfName: "eth0", ItemRef: ref}}
	tc2Same := TCIngress{NetIf: generic.NetworkIf{IfName: "eth0", ItemRef: ref}}
	tc3Diff := TCIngress{NetIf: generic.NetworkIf{IfName: "eth1"}}
	if !tc1.Equal(tc2Same) {
		t.Error("identical TCIngress should be equal")
	}
	if tc1.Equal(tc3Diff) {
		t.Error("different NetIf should be unequal")
	}
	if tc1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestTCIngressDependencies(t *testing.T) {
	ref := dg.ItemRef{ItemType: "Port", ItemName: "eth0"}
	tc := TCIngress{NetIf: generic.NetworkIf{IfName: "eth0", ItemRef: ref}}
	deps := tc.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem != ref {
		t.Errorf("dep should be NetIf")
	}
	if !deps[0].Attributes.AutoDeletedByExternal {
		t.Error("dep should be AutoDeletedByExternal")
	}
}

// --- TCMirror ---

func TestTCMirrorName(t *testing.T) {
	tc := TCMirror{FromNetIf: generic.NetworkIf{IfName: "eth0"}, RulePriority: 10}
	if got := tc.Name(); got != "tc-mirror/eth0/10" {
		t.Errorf("got %q", got)
	}
}

func TestTCMirrorLabel(t *testing.T) {
	tc := TCMirror{
		FromNetIf:    generic.NetworkIf{IfName: "eth0"},
		ToNetIf:      generic.NetworkIf{IfName: "br0"},
		RulePriority: 5,
	}
	if got := tc.Label(); got == "" {
		t.Error("expected non-empty label")
	}
}

func TestTCMirrorType(t *testing.T) {
	tc := TCMirror{}
	if got := tc.Type(); got != TCMirrorTypename {
		t.Errorf("got %q, want %q", got, TCMirrorTypename)
	}
}

func TestTCMirrorExternal(t *testing.T) {
	tc := TCMirror{}
	if tc.External() {
		t.Error("expected External() = false")
	}
}

func TestTCMirrorString(t *testing.T) {
	tc := TCMirror{
		FromNetIf:         generic.NetworkIf{IfName: "eth0"},
		ToNetIf:           generic.NetworkIf{IfName: "br0"},
		Protocol:          TCMatchProtoIPv4,
		TransportProtocol: uint8Ptr(6),
	}
	if s := tc.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestTCMirrorEqual(t *testing.T) {
	toRef := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	tc1 := TCMirror{
		FromNetIf: generic.NetworkIf{IfName: "eth0"},
		ToNetIf:   generic.NetworkIf{IfName: "br0", ItemRef: toRef},
		Protocol:  TCMatchProtoIPv4,
	}
	tc2Same := TCMirror{
		FromNetIf: generic.NetworkIf{IfName: "eth1"}, // FromNetIf not compared by Equal
		ToNetIf:   generic.NetworkIf{IfName: "br0", ItemRef: toRef},
		Protocol:  TCMatchProtoIPv4,
	}
	tc3DiffProto := TCMirror{
		FromNetIf: generic.NetworkIf{IfName: "eth0"},
		ToNetIf:   generic.NetworkIf{IfName: "br0", ItemRef: toRef},
		Protocol:  TCMatchProtoIPv6,
	}
	if !tc1.Equal(tc2Same) {
		t.Error("same ToNetIf+Protocol should be equal")
	}
	if tc1.Equal(tc3DiffProto) {
		t.Error("different Protocol should be unequal")
	}
	if tc1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestTCMirrorDependencies(t *testing.T) {
	fromRef := dg.ItemRef{ItemType: "Port", ItemName: "eth0"}
	toRef := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	tc := TCMirror{
		FromNetIf: generic.NetworkIf{IfName: "eth0", ItemRef: fromRef},
		ToNetIf:   generic.NetworkIf{IfName: "br0", ItemRef: toRef},
	}
	deps := tc.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	// First dep: TCIngress for FromNetIf
	if deps[0].RequiredItem.ItemType != TCIngressTypename {
		t.Errorf("first dep should be TCIngress, got %q", deps[0].RequiredItem.ItemType)
	}
	// Second dep: ToNetIf
	if deps[1].RequiredItem != toRef {
		t.Errorf("second dep should be ToNetIf")
	}
}

// --- VIF ---

func TestVIFName(t *testing.T) {
	v := VIF{HostIfName: "vif0"}
	if got := v.Name(); got != "vif0" {
		t.Errorf("got %q", got)
	}
}

func TestVIFLabel(t *testing.T) {
	v := VIF{HostIfName: "vif0", NetAdapterName: "adapter0"}
	if got := v.Label(); got != "adapter0 (vif0)" {
		t.Errorf("got %q", got)
	}
}

func TestVIFType(t *testing.T) {
	v := VIF{}
	if got := v.Type(); got != VIFTypename {
		t.Errorf("got %q, want %q", got, VIFTypename)
	}
}

func TestVIFExternal(t *testing.T) {
	vExt := VIF{Variant: VIFVariant{External: true}}
	vInt := VIF{Variant: VIFVariant{External: false}}
	if !vExt.External() {
		t.Error("External variant should return true")
	}
	if vInt.External() {
		t.Error("Veth variant should return false")
	}
}

func TestVIFString(t *testing.T) {
	v := VIF{HostIfName: "vif0", Variant: VIFVariant{External: true}}
	if s := v.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestVIFGetAssignedIPs(t *testing.T) {
	ip := &net.IPNet{IP: net.IP{10, 0, 0, 2}, Mask: net.CIDRMask(24, 32)}
	vExt := VIF{Variant: VIFVariant{External: true}}
	vVeth := VIF{Variant: VIFVariant{Veth: Veth{AppIPs: []*net.IPNet{ip}}}}
	if ips := vExt.GetAssignedIPs(); ips != nil {
		t.Errorf("external VIF: expected nil IPs, got %v", ips)
	}
	if ips := vVeth.GetAssignedIPs(); len(ips) != 1 {
		t.Errorf("veth VIF: expected 1 IP, got %d", len(ips))
	}
}

func TestVIFGetMTU(t *testing.T) {
	vExt := VIF{Variant: VIFVariant{External: true}}
	if got := vExt.GetMTU(); got != 0 {
		t.Errorf("external VIF MTU: got %d, want 0", got)
	}
	vVeth0 := VIF{Variant: VIFVariant{Veth: Veth{MTU: 0}}}
	if got := vVeth0.GetMTU(); got != types.DefaultMTU {
		t.Errorf("veth zero MTU: got %d, want DefaultMTU", got)
	}
	vVeth9000 := VIF{Variant: VIFVariant{Veth: Veth{MTU: 9000}}}
	if got := vVeth9000.GetMTU(); got != 9000 {
		t.Errorf("veth MTU: got %d, want 9000", got)
	}
}

func TestVIFEqual(t *testing.T) {
	v1 := VIF{HostIfName: "vif0", NetAdapterName: "a", Variant: VIFVariant{External: true}}
	v2Same := VIF{HostIfName: "vif0", NetAdapterName: "a", Variant: VIFVariant{External: true}}
	v3DiffName := VIF{HostIfName: "vif1", NetAdapterName: "a", Variant: VIFVariant{External: true}}
	if !v1.Equal(v2Same) {
		t.Error("identical VIFs should be equal")
	}
	if v1.Equal(v3DiffName) {
		t.Error("different HostIfName should be unequal")
	}
	if v1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestVIFDependencies(t *testing.T) {
	v := VIF{}
	if deps := v.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

// --- VLANBridge ---

func TestVLANBridgeName(t *testing.T) {
	v := VLANBridge{BridgeIfName: "br0"}
	if got := v.Name(); got != "br0" {
		t.Errorf("got %q", got)
	}
}

func TestVLANBridgeLabel(t *testing.T) {
	v := VLANBridge{BridgeIfName: "br0"}
	if got := v.Label(); got != "br0 (VLAN bridge)" {
		t.Errorf("got %q", got)
	}
}

func TestVLANBridgeType(t *testing.T) {
	v := VLANBridge{}
	if got := v.Type(); got != VLANBridgeTypename {
		t.Errorf("got %q, want %q", got, VLANBridgeTypename)
	}
}

func TestVLANBridgeExternal(t *testing.T) {
	v := VLANBridge{}
	if v.External() {
		t.Error("expected External() = false")
	}
}

func TestVLANBridgeString(t *testing.T) {
	v := VLANBridge{BridgeIfName: "br0", EnableVLANFiltering: true}
	if s := v.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestVLANBridgeEqual(t *testing.T) {
	v1 := VLANBridge{BridgeIfName: "br0", EnableVLANFiltering: true}
	v2Same := VLANBridge{BridgeIfName: "br0", EnableVLANFiltering: true}
	v3Diff := VLANBridge{BridgeIfName: "br0", EnableVLANFiltering: false}
	if !v1.Equal(v2Same) {
		t.Error("identical VLANBridges should be equal")
	}
	if v1.Equal(v3Diff) {
		t.Error("different EnableVLANFiltering should be unequal")
	}
	if v1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestVLANBridgeDependencies(t *testing.T) {
	v := VLANBridge{BridgeIfName: "br0"}
	deps := v.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != BridgeTypename || deps[0].RequiredItem.ItemName != "br0" {
		t.Errorf("dep should be Bridge br0, got %+v", deps[0].RequiredItem)
	}
}

// --- VLANPort ---

func TestVLANPortName(t *testing.T) {
	v := VLANPort{BridgeIfName: "br0", PortIfName: "eth0"}
	if got := v.Name(); got != "br0/eth0" {
		t.Errorf("got %q", got)
	}
}

func TestVLANPortLabel(t *testing.T) {
	v := VLANPort{BridgeIfName: "br0", PortIfName: "eth0"}
	if got := v.Label(); got == "" {
		t.Error("expected non-empty label")
	}
}

func TestVLANPortType(t *testing.T) {
	v := VLANPort{}
	if got := v.Type(); got != VLANPortTypename {
		t.Errorf("got %q, want %q", got, VLANPortTypename)
	}
}

func TestVLANPortExternal(t *testing.T) {
	v := VLANPort{}
	if v.External() {
		t.Error("expected External() = false")
	}
}

func TestVLANPortString(t *testing.T) {
	v := VLANPort{
		BridgeIfName: "br0",
		PortIfName:   "eth0",
		VLANConfig:   VLANConfig{AccessPort: &AccessPort{VID: 100}},
	}
	if s := v.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestVLANPortEqual(t *testing.T) {
	v1 := VLANPort{
		BridgeIfName: "br0", PortIfName: "eth0",
		VLANConfig: VLANConfig{AccessPort: &AccessPort{VID: 100}},
	}
	v2Same := VLANPort{
		BridgeIfName: "br0", PortIfName: "eth0",
		VLANConfig: VLANConfig{AccessPort: &AccessPort{VID: 100}},
	}
	v3DiffVID := VLANPort{
		BridgeIfName: "br0", PortIfName: "eth0",
		VLANConfig: VLANConfig{AccessPort: &AccessPort{VID: 200}},
	}
	v4Trunk := VLANPort{
		BridgeIfName: "br0", PortIfName: "eth0",
		VLANConfig: VLANConfig{TrunkPort: &TrunkPort{AllVIDs: true}},
	}
	if !v1.Equal(v2Same) {
		t.Error("identical VLANPorts should be equal")
	}
	if v1.Equal(v3DiffVID) {
		t.Error("different VID should be unequal")
	}
	if v1.Equal(v4Trunk) {
		t.Error("access vs trunk should be unequal")
	}
	if v1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestVLANPortEqualTrunk(t *testing.T) {
	v1 := VLANPort{
		VLANConfig: VLANConfig{TrunkPort: &TrunkPort{VIDs: []uint16{10, 20}}},
	}
	v2OrderDiff := VLANPort{
		VLANConfig: VLANConfig{TrunkPort: &TrunkPort{VIDs: []uint16{20, 10}}},
	}
	v3AllVIDs := VLANPort{
		VLANConfig: VLANConfig{TrunkPort: &TrunkPort{AllVIDs: true}},
	}
	if !v1.Equal(v2OrderDiff) {
		t.Error("trunk VIDs equality should be order-independent")
	}
	if v1.Equal(v3AllVIDs) {
		t.Error("AllVIDs=false vs true should be unequal")
	}
}

func TestVLANPortDependencies(t *testing.T) {
	v := VLANPort{
		BridgeIfName: "br0", PortIfName: "eth0",
		VLANConfig: VLANConfig{AccessPort: &AccessPort{VID: 100}},
	}
	deps := v.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != VLANBridgeTypename {
		t.Errorf("first dep should be VLANBridge, got %q", deps[0].RequiredItem.ItemType)
	}
	if deps[1].RequiredItem.ItemType != BridgePortTypename {
		t.Errorf("second dep should be BridgePort, got %q", deps[1].RequiredItem.ItemType)
	}
}

// --- VLANSubIf ---

func TestVLANSubIfName(t *testing.T) {
	v := VLANSubIf{IfName: "eth0.100"}
	if got := v.Name(); got != "eth0.100" {
		t.Errorf("got %q", got)
	}
}

func TestVLANSubIfLabel(t *testing.T) {
	v := VLANSubIf{LogicalLabel: "uplink.100"}
	if got := v.Label(); got != "uplink.100 (VLAN sub-interface)" {
		t.Errorf("got %q", got)
	}
}

func TestVLANSubIfType(t *testing.T) {
	v := VLANSubIf{}
	if got := v.Type(); got != VLANSubIntfTypename {
		t.Errorf("got %q, want %q", got, VLANSubIntfTypename)
	}
}

func TestVLANSubIfExternal(t *testing.T) {
	v := VLANSubIf{}
	if !v.External() {
		t.Error("expected External() = true")
	}
}

func TestVLANSubIfString(t *testing.T) {
	v := VLANSubIf{IfName: "eth0.100", LogicalLabel: "uplink.100", ParentIfName: "eth0", ID: 100}
	if s := v.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestVLANSubIfEqual(t *testing.T) {
	v1 := VLANSubIf{IfName: "eth0.100", ParentIfName: "eth0", ID: 100}
	v2Same := VLANSubIf{IfName: "eth0.100", ParentIfName: "eth0", ID: 100}
	v3DiffID := VLANSubIf{IfName: "eth0.100", ParentIfName: "eth0", ID: 200}
	v4DiffParent := VLANSubIf{IfName: "eth0.100", ParentIfName: "eth1", ID: 100}
	if !v1.Equal(v2Same) {
		t.Error("identical VLANSubIf instances should be equal")
	}
	if v1.Equal(v3DiffID) {
		t.Error("different ID should be unequal")
	}
	if v1.Equal(v4DiffParent) {
		t.Error("different ParentIfName should be unequal")
	}
}

func TestVLANSubIfDependencies(t *testing.T) {
	v := VLANSubIf{}
	if deps := v.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

// --- Route ---

func TestRouteIpVersionStr(t *testing.T) {
	tests := []struct {
		family int
		want   string
	}{
		{netlink.FAMILY_V4, "IPv4"},
		{netlink.FAMILY_V6, "IPv6"},
		{99, "Unsupported (family 99)"},
	}
	for _, tc := range tests {
		r := Route{Route: netlink.Route{Family: tc.family}}
		if got := r.ipVersionStr(); got != tc.want {
			t.Errorf("family %d: got %q, want %q", tc.family, got, tc.want)
		}
	}
}

func TestRouteHasDefaultDst(t *testing.T) {
	tests := []struct {
		name string
		dst  *net.IPNet
		want bool
	}{
		{"nil", nil, true},
		{"0.0.0.0/0", mustParseCIDRLI("0.0.0.0/0"), true},
		{"::/0", mustParseCIDRLI("::/0"), true},
		{"10.0.0.0/8", mustParseCIDRLI("10.0.0.0/8"), false},
		{"192.168.1.0/24", mustParseCIDRLI("192.168.1.0/24"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{Route: netlink.Route{Dst: tc.dst}}
			if got := r.hasDefaultDst(); got != tc.want {
				t.Errorf("hasDefaultDst() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouteNormalizedNetlinkRoute(t *testing.T) {
	// nil Dst for IPv4 should become 0.0.0.0/0
	r := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Dst: nil}}
	norm := r.normalizedNetlinkRoute()
	if norm.Dst == nil {
		t.Error("normalized route should have non-nil Dst")
	}
	ones, _ := norm.Dst.Mask.Size()
	if ones != 0 || !norm.Dst.IP.IsUnspecified() {
		t.Errorf("normalized Dst should be 0.0.0.0/0, got %s", norm.Dst)
	}
	// Flags should be cleared
	r2 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Flags: 0x10, Dst: mustParseCIDRLI("10.0.0.0/8")}}
	norm2 := r2.normalizedNetlinkRoute()
	if norm2.Flags != 0 {
		t.Errorf("flags should be cleared, got %d", norm2.Flags)
	}
}

func TestRouteName(t *testing.T) {
	// No app, no output interface, nil dst
	r1 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Table: 254}}
	if got := r1.Name(); got != "254/default" {
		t.Errorf("got %q, want %q", got, "254/default")
	}
	// With output interface and specific dst
	r2 := Route{
		Route:    netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: mustParseCIDRLI("10.0.0.0/8")},
		OutputIf: generic.NetworkIf{IfName: "eth0"},
	}
	if got := r2.Name(); got != "254/eth0/10.0.0.0/8" {
		t.Errorf("got %q, want %q", got, "254/eth0/10.0.0.0/8")
	}
}

func TestRouteType(t *testing.T) {
	r4 := Route{Route: netlink.Route{Family: netlink.FAMILY_V4}}
	if got := r4.Type(); got != generic.IPv4RouteTypename {
		t.Errorf("IPv4: got %q", got)
	}
	r6 := Route{Route: netlink.Route{Family: netlink.FAMILY_V6}}
	if got := r6.Type(); got != generic.IPv6RouteTypename {
		t.Errorf("IPv6: got %q", got)
	}
	rUnk := Route{Route: netlink.Route{Family: 99}}
	if got := rUnk.Type(); got != generic.UnsupportedRouteTypename {
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
	r := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Table: 254}, OutputIf: generic.NetworkIf{IfName: "eth0"}}
	if s := r.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestRouteEqual(t *testing.T) {
	r1 := Route{
		Route:    netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: mustParseCIDRLI("10.0.0.0/8")},
		OutputIf: generic.NetworkIf{IfName: "eth0"},
	}
	r2Same := Route{
		Route:    netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: mustParseCIDRLI("10.0.0.0/8")},
		OutputIf: generic.NetworkIf{IfName: "eth0"},
	}
	r3DiffDst := Route{
		Route:    netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: mustParseCIDRLI("192.168.0.0/16")},
		OutputIf: generic.NetworkIf{IfName: "eth0"},
	}
	r4DiffIf := Route{
		Route:    netlink.Route{Family: netlink.FAMILY_V4, Table: 254, Dst: mustParseCIDRLI("10.0.0.0/8")},
		OutputIf: generic.NetworkIf{IfName: "eth1"},
	}
	if !r1.Equal(r2Same) {
		t.Error("identical routes should be equal")
	}
	if r1.Equal(r3DiffDst) {
		t.Error("different Dst should be unequal")
	}
	if r1.Equal(r4DiffIf) {
		t.Error("different OutputIf should be unequal")
	}
	if r1.Equal(DummyIf{}) {
		t.Error("wrong type should be unequal")
	}
}

func TestRouteDependenciesWithGw(t *testing.T) {
	ifRef := dg.ItemRef{ItemType: "Bridge", ItemName: "br0"}
	gw := net.IP{10, 0, 0, 254}
	r := Route{
		Route: netlink.Route{
			Family: netlink.FAMILY_V4,
			Table:  254,
			Dst:    mustParseCIDRLI("0.0.0.0/0"),
			Gw:     gw,
		},
		OutputIf: generic.NetworkIf{IfName: "br0", ItemRef: ifRef},
	}
	deps := r.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem != ifRef {
		t.Errorf("dep should be OutputIf")
	}
	if deps[0].MustSatisfy == nil {
		t.Error("dep should have MustSatisfy")
	}
	// Port with subnet containing gw → true
	portMatch := generic.Port{
		IPAddresses: []*net.IPNet{{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(24, 32)}},
	}
	if !deps[0].MustSatisfy(portMatch) {
		t.Error("MustSatisfy should be true when gw is in assigned subnet")
	}
	// Port with subnet not containing gw → false
	portNoMatch := generic.Port{
		IPAddresses: []*net.IPNet{{IP: net.IP{192, 168, 0, 1}, Mask: net.CIDRMask(24, 32)}},
	}
	if deps[0].MustSatisfy(portNoMatch) {
		t.Error("MustSatisfy should be false when gw not in assigned subnet")
	}
}

func TestRouteDependenciesNoOutputIf(t *testing.T) {
	r := Route{Route: netlink.Route{Family: netlink.FAMILY_V4, Table: 254}}
	deps := r.Dependencies()
	if len(deps) != 0 {
		t.Errorf("route without output interface should have no deps, got %d", len(deps))
	}
}

func TestRouteDependenciesLoopback(t *testing.T) {
	r := Route{
		Route:    netlink.Route{Family: netlink.FAMILY_V4, Table: 254},
		OutputIf: generic.NetworkIf{IfName: "lo"},
	}
	deps := r.Dependencies()
	if len(deps) != 0 {
		t.Errorf("loopback route should have no deps, got %d", len(deps))
	}
}
