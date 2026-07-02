// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmonitor

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// --- Route.IsDefaultRoute ---

func TestRouteIsDefaultRoute(t *testing.T) {
	tests := []struct {
		name string
		dst  *net.IPNet
		want bool
	}{
		{"nil Dst", nil, true},
		{"0.0.0.0/0", mustParseCIDR("0.0.0.0/0"), true},
		{"::/0", mustParseCIDR("::/0"), true},
		{"192.168.0.0/16", mustParseCIDR("192.168.0.0/16"), false},
		{"10.0.0.0/8", mustParseCIDR("10.0.0.0/8"), false},
		{"0.0.0.0/8", mustParseCIDR("0.0.0.0/8"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{Dst: tc.dst}
			if got := r.IsDefaultRoute(); got != tc.want {
				t.Errorf("IsDefaultRoute() = %v, want %v", got, tc.want)
			}
		})
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

// --- IfAttrs.Equal ---

func TestIfAttrsEqual(t *testing.T) {
	base := IfAttrs{
		IfIndex: 2, IfName: "eth0", IfType: "ether",
		IsLoopback: false, WithBroadcast: true,
		AdminUp: true, LowerUp: true,
		Enslaved: false, MasterIfIndex: 0,
		MTU: 1500,
	}
	mod := func(f func(*IfAttrs)) IfAttrs {
		a := base
		f(&a)
		return a
	}
	tests := []struct {
		name  string
		other IfAttrs
		want  bool
	}{
		{"identical", base, true},
		{"diff IfIndex", mod(func(a *IfAttrs) { a.IfIndex = 3 }), false},
		{"diff IfName", mod(func(a *IfAttrs) { a.IfName = "eth1" }), false},
		{"diff IfType", mod(func(a *IfAttrs) { a.IfType = "bond" }), false},
		{"diff AdminUp", mod(func(a *IfAttrs) { a.AdminUp = false }), false},
		{"diff LowerUp", mod(func(a *IfAttrs) { a.LowerUp = false }), false},
		{"diff MTU", mod(func(a *IfAttrs) { a.MTU = 9000 }), false},
		{"diff Enslaved", mod(func(a *IfAttrs) { a.Enslaved = true; a.MasterIfIndex = 5 }), false},
		{"diff VlanID", mod(func(a *IfAttrs) { a.VlanID = 10 }), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- IfChange.Equal ---

func TestIfChangeEqual(t *testing.T) {
	base := IfChange{
		Attrs:   IfAttrs{IfIndex: 2, IfName: "eth0", MTU: 1500},
		Added:   false,
		Deleted: false,
	}
	same := IfChange{
		Attrs:   IfAttrs{IfIndex: 2, IfName: "eth0", MTU: 1500},
		Added:   false,
		Deleted: false,
	}
	diffAdded := IfChange{
		Attrs:   IfAttrs{IfIndex: 2, IfName: "eth0", MTU: 1500},
		Added:   true,
		Deleted: false,
	}
	diffAttrs := IfChange{
		Attrs:   IfAttrs{IfIndex: 2, IfName: "eth1", MTU: 1500},
		Added:   false,
		Deleted: false,
	}
	if !base.Equal(same) {
		t.Error("identical IfChange should be equal")
	}
	if base.Equal(diffAdded) {
		t.Error("diff Added should not be equal")
	}
	if base.Equal(diffAttrs) {
		t.Error("diff Attrs should not be equal")
	}
}

// --- isNetworkEvent marker methods ---

func TestIsNetworkEventMarkers(t *testing.T) {
	// Ensure all Event implementations satisfy the interface.
	// Calling isNetworkEvent() directly covers the marker bodies.
	events := []Event{
		RouteChange{},
		AddrChange{},
		IfChange{},
		DNSInfoChange{},
		PNACEvent{},
		BondActiveMemberChange{},
	}
	for _, e := range events {
		e.isNetworkEvent()
	}
}

// --- parseChurnState ---

func TestParseChurnState(t *testing.T) {
	tests := []struct {
		input string
		want  types.BondLACPChurnState
	}{
		{"none", types.BondLACPChurnNone},
		{"monitoring", types.BondLACPChurnMonitoring},
		{"churned", types.BondLACPChurnChurned},
		{"", types.BondLACPChurnNone},
		{"unknown", types.BondLACPChurnNone},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := parseChurnState(tc.input); got != tc.want {
				t.Errorf("parseChurnState(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// --- isDhcpcdNotRunningErr ---

func TestIsDhcpcdNotRunningErr(t *testing.T) {
	m := &LinuxNetworkMonitor{}
	tests := []struct {
		input string
		want  bool
	}{
		{"dhcpcd is not running", true},
		{"prefix dhcpcd is not running suffix", true},
		{"dhcp_dump: No such file or directory", true},
		{"some other error message", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			if got := m.isDhcpcdNotRunningErr(tc.input); got != tc.want {
				t.Errorf("isDhcpcdNotRunningErr(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// --- parseProcBondInfo ---

const testProcBondInfoContent = `Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
MII Status: up
Peer Notification Delay (ms): 100
ARP Missed Max: 5

802.3ad info
Active Aggregator Info:
	Aggregator ID: 2
	Actor Key: 9
	Partner Key: 9
	Partner Mac Address: 00:aa:bb:cc:dd:ee

Slave Interface: eth0
MII Status: up
Aggregator ID: 2
Actor Churn State: none
Partner Churn State: monitoring

Slave Interface: eth1
MII Status: down
Aggregator ID: 3
Actor Churn State: churned
Partner Churn State: churned
`

func writeTempBondFile(t *testing.T, content string) (dir, name string) {
	t.Helper()
	dir = t.TempDir()
	name = "bond0"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp bond file: %v", err)
	}
	return dir, name
}

func TestParseProcBondInfo(t *testing.T) {
	dir, name := writeTempBondFile(t, testProcBondInfoContent)

	info, err := parseProcBondInfo(dir, name)
	if err != nil {
		t.Fatalf("parseProcBondInfo: unexpected error: %v", err)
	}

	if info.peerNotificationDelay != 100 {
		t.Errorf("peerNotificationDelay: got %d, want 100", info.peerNotificationDelay)
	}
	if info.arpMissedMax != 5 {
		t.Errorf("arpMissedMax: got %d, want 5", info.arpMissedMax)
	}
	if info.lacpInfo == nil {
		t.Fatal("lacpInfo is nil")
	}
	if info.lacpInfo.AggregatorID != 2 {
		t.Errorf("lacpInfo.AggregatorID: got %d, want 2", info.lacpInfo.AggregatorID)
	}
	if info.lacpInfo.ActorKey != 9 {
		t.Errorf("lacpInfo.ActorKey: got %d, want 9", info.lacpInfo.ActorKey)
	}
	if info.lacpInfo.PartnerKey != 9 {
		t.Errorf("lacpInfo.PartnerKey: got %d, want 9", info.lacpInfo.PartnerKey)
	}
	wantMAC, _ := net.ParseMAC("00:aa:bb:cc:dd:ee")
	if info.lacpInfo.PartnerMAC.String() != wantMAC.String() {
		t.Errorf("lacpInfo.PartnerMAC: got %v, want %v", info.lacpInfo.PartnerMAC, wantMAC)
	}
	if len(info.members) != 2 {
		t.Fatalf("members: got %d, want 2", len(info.members))
	}
	m0 := info.members[0]
	if m0.ifName != "eth0" {
		t.Errorf("members[0].ifName: got %q, want %q", m0.ifName, "eth0")
	}
	if !m0.miiUp {
		t.Error("members[0].miiUp: want true")
	}
	if m0.aggregatorID != 2 {
		t.Errorf("members[0].aggregatorID: got %d, want 2", m0.aggregatorID)
	}
	if m0.actorChurnState != types.BondLACPChurnNone {
		t.Errorf("members[0].actorChurnState: got %v, want None", m0.actorChurnState)
	}
	if m0.partnerChurnState != types.BondLACPChurnMonitoring {
		t.Errorf("members[0].partnerChurnState: got %v, want Monitoring", m0.partnerChurnState)
	}
	m1 := info.members[1]
	if m1.ifName != "eth1" {
		t.Errorf("members[1].ifName: got %q, want %q", m1.ifName, "eth1")
	}
	if m1.miiUp {
		t.Error("members[1].miiUp: want false")
	}
	if m1.aggregatorID != 3 {
		t.Errorf("members[1].aggregatorID: got %d, want 3", m1.aggregatorID)
	}
	if m1.actorChurnState != types.BondLACPChurnChurned {
		t.Errorf("members[1].actorChurnState: got %v, want Churned", m1.actorChurnState)
	}
	if m1.partnerChurnState != types.BondLACPChurnChurned {
		t.Errorf("members[1].partnerChurnState: got %v, want Churned", m1.partnerChurnState)
	}
}

func TestParseProcBondInfoNotFound(t *testing.T) {
	_, err := parseProcBondInfo(t.TempDir(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// --- parseProcBondMemberMetrics ---

const testProcBondMemberMetricsContent = `Ethernet Channel Bonding Driver: v3.7.1 (April 27, 2011)

Bonding Mode: IEEE 802.3ad Dynamic link aggregation

Slave Interface: eth0
Actor Churned Count: 3
Partner Churned Count: 7

Slave Interface: eth1
Actor Churned Count: 0
Partner Churned Count: 2
`

func TestParseProcBondMemberMetrics(t *testing.T) {
	dir, name := writeTempBondFile(t, testProcBondMemberMetricsContent)

	metrics, err := parseProcBondMemberMetrics(dir, name)
	if err != nil {
		t.Fatalf("parseProcBondMemberMetrics: unexpected error: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("metrics: got %d entries, want 2", len(metrics))
	}
	if m := metrics["eth0"]; m.actorChurnedCount != 3 || m.partnerChurnedCount != 7 {
		t.Errorf("eth0: got actor=%d partner=%d, want 3/7",
			m.actorChurnedCount, m.partnerChurnedCount)
	}
	if m := metrics["eth1"]; m.actorChurnedCount != 0 || m.partnerChurnedCount != 2 {
		t.Errorf("eth1: got actor=%d partner=%d, want 0/2",
			m.actorChurnedCount, m.partnerChurnedCount)
	}
}

func TestParseProcBondMemberMetricsEmpty(t *testing.T) {
	dir, name := writeTempBondFile(t, "")

	metrics, err := parseProcBondMemberMetrics(dir, name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(metrics) != 0 {
		t.Errorf("expected empty map, got %d entries", len(metrics))
	}
}

func TestParseProcBondMemberMetricsNotFound(t *testing.T) {
	_, err := parseProcBondMemberMetrics(t.TempDir(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
