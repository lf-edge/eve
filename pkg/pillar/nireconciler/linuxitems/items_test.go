// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"net"
	"testing"

	dg "github.com/lf-edge/eve-libs/depgraph"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

func mustParseCIDRLI(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

func uint32Ptr(v uint32) *uint32 { return &v }

// depByType returns the first dependency on the given item type. Tests use this
// instead of positional indexing so that reordering dependencies (which is
// semantically irrelevant to the reconciler) does not break them.
func depByType(t *testing.T, deps []dg.Dependency, itemType string) dg.Dependency {
	t.Helper()
	for _, d := range deps {
		if d.RequiredItem.ItemType == itemType {
			return d
		}
	}
	t.Fatalf("no dependency on item type %q; got %v", itemType, deps)
	return dg.Dependency{}
}

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

// --- BPDUGuard ---

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
	depByType(t, deps, BridgeTypename)
	bpDep := depByType(t, deps, BridgePortTypename)
	wantBPName := BridgePortName("br0", "eth0")
	if bpDep.RequiredItem.ItemName != wantBPName {
		t.Errorf("BridgePort dep name: got %q, want %q", bpDep.RequiredItem.ItemName, wantBPName)
	}
}

// --- BridgeFwdMask ---

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
	for _, dep := range deps {
		if dep.MustSatisfy == nil {
			t.Fatalf("every IP dependency should have MustSatisfy, got %+v", dep)
		}
	}
	// Each configured IP must be satisfied by some dependency, without assuming
	// which dependency corresponds to which address.
	for _, ip := range b.IPAddresses {
		matchingReserve := generic.IPReserve{
			AddrWithMask: ip,
			NetIf:        generic.NetworkIf{ItemRef: dg.Reference(b)},
		}
		satisfied := false
		for _, dep := range deps {
			if dep.MustSatisfy(matchingReserve) {
				satisfied = true
				break
			}
		}
		if !satisfied {
			t.Errorf("no dependency satisfied by IPReserve for %v", ip)
		}
	}
	// An IPReserve for a different NetIf must satisfy none of the dependencies.
	nonMatchingReserve := generic.IPReserve{
		AddrWithMask: b.IPAddresses[0],
		NetIf:        generic.NetworkIf{ItemRef: dg.ItemRef{ItemType: "Bridge", ItemName: "other"}},
	}
	for _, dep := range deps {
		if dep.MustSatisfy(nonMatchingReserve) {
			t.Error("MustSatisfy should return false for non-matching NetIf")
		}
	}
}

// --- BridgePort ---

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
	depByType(t, deps, BridgeTypename)
	vifDep := depByType(t, deps, VIFTypename)
	if vifDep.RequiredItem.ItemName != "vif0" {
		t.Errorf("VIF dep name: got %q, want %q", vifDep.RequiredItem.ItemName, "vif0")
	}
}

func TestBridgePortDependenciesPort(t *testing.T) {
	// ExternallyBridged=false: no MustSatisfy
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	portDep := depByType(t, deps, generic.PortTypename)
	if portDep.MustSatisfy != nil {
		t.Error("non-externally bridged port dep should not have MustSatisfy")
	}
}

func TestBridgePortDependenciesPortExternallyBridged(t *testing.T) {
	p := BridgePort{BridgeIfName: "br0", Variant: BridgePortVariant{PortIfName: "eth0"}, ExternallyBridged: true}
	deps := p.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	portDep := depByType(t, deps, generic.PortTypename)
	if portDep.MustSatisfy == nil {
		t.Fatal("externally bridged port dep should have MustSatisfy")
	}
	// Port with matching MasterIfName → true
	portMatch := generic.Port{MasterIfName: "br0"}
	if !portDep.MustSatisfy(portMatch) {
		t.Error("MustSatisfy should be true for matching MasterIfName")
	}
	portNoMatch := generic.Port{MasterIfName: "br1"}
	if portDep.MustSatisfy(portNoMatch) {
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
	subIfDep := depByType(t, deps, VLANSubIntfTypename)
	if subIfDep.MustSatisfy == nil {
		t.Fatal("VLANSubinterface dep should have MustSatisfy")
	}
	// VLANSubIf with matching ParentIfName and ID → true
	match := VLANSubIf{ParentIfName: "br0", ID: 100}
	if !subIfDep.MustSatisfy(match) {
		t.Error("MustSatisfy should be true for matching VLANSubIf")
	}
	noMatch := VLANSubIf{ParentIfName: "br0", ID: 200}
	if subIfDep.MustSatisfy(noMatch) {
		t.Error("MustSatisfy should be false for wrong VID")
	}
}

// --- DummyIf ---

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

func TestIPRuleDependencies(t *testing.T) {
	r := IPRule{}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
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
	// One dep is a TCIngress for FromNetIf.
	depByType(t, deps, TCIngressTypename)
	// The other references ToNetIf.
	foundTo := false
	for _, d := range deps {
		if d.RequiredItem == toRef {
			foundTo = true
		}
	}
	if !foundTo {
		t.Errorf("expected a dependency on ToNetIf %v, got %v", toRef, deps)
	}
}

// --- VIF ---

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
	depByType(t, deps, VLANBridgeTypename)
	depByType(t, deps, BridgePortTypename)
}

// --- VLANSubIf ---

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
