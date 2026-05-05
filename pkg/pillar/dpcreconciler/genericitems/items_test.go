// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"net"
	"testing"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// --- AdapterAddrs ---

func TestAdapterAddrsName(t *testing.T) {
	a := AdapterAddrs{AdapterIfName: "eth0", AdapterLL: "eth0-label"}
	if got := a.Name(); got != "eth0" {
		t.Errorf("got %q, want %q", got, "eth0")
	}
}

func TestAdapterAddrsLabel(t *testing.T) {
	a := AdapterAddrs{AdapterLL: "eth0-label"}
	if got := a.Label(); got != "eth0-label IP addresses" {
		t.Errorf("got %q", got)
	}
}

func TestAdapterAddrsType(t *testing.T) {
	a := AdapterAddrs{}
	if got := a.Type(); got != AdapterAddrsTypename {
		t.Errorf("got %q, want %q", got, AdapterAddrsTypename)
	}
}

func TestAdapterAddrsExternal(t *testing.T) {
	a := AdapterAddrs{}
	if !a.External() {
		t.Error("expected External() = true")
	}
}

func TestAdapterAddrsDependencies(t *testing.T) {
	a := AdapterAddrs{}
	if deps := a.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestAdapterAddrsString(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	a := AdapterAddrs{AdapterLL: "eth0", IPAddrs: []*net.IPNet{subnet}}
	if s := a.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestAdapterAddrsEqual(t *testing.T) {
	_, net1, _ := net.ParseCIDR("10.0.0.0/24")
	_, net2, _ := net.ParseCIDR("10.0.1.0/24")
	a1 := AdapterAddrs{AdapterIfName: "eth0", IPAddrs: []*net.IPNet{net1, net2}}
	a2Same := AdapterAddrs{AdapterIfName: "eth0", IPAddrs: []*net.IPNet{net2, net1}}
	a3Less := AdapterAddrs{AdapterIfName: "eth0", IPAddrs: []*net.IPNet{net1}}
	a4Empty := AdapterAddrs{}
	tests := []struct {
		name  string
		a     AdapterAddrs
		other dg.Item
		want  bool
	}{
		{"identical", a1, a1, true},
		{"order-independent", a1, a2Same, true},
		{"subset", a1, a3Less, false},
		{"both empty", a4Empty, a4Empty, true},
		{"wrong type", a1, ResolvConf{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Dhcpcd (Name/Label/Type/External/String/Dependencies not yet covered) ---

func TestDhcpcdName(t *testing.T) {
	c := Dhcpcd{AdapterIfName: "eth0", AdapterLL: "eth0-label"}
	if got := c.Name(); got != "eth0" {
		t.Errorf("got %q, want %q", got, "eth0")
	}
}

func TestDhcpcdLabel(t *testing.T) {
	c := Dhcpcd{AdapterLL: "eth0-label"}
	if got := c.Label(); got != "dhcpcd for eth0-label" {
		t.Errorf("got %q", got)
	}
}

func TestDhcpcdType(t *testing.T) {
	c := Dhcpcd{}
	if got := c.Type(); got != DhcpcdTypename {
		t.Errorf("got %q, want %q", got, DhcpcdTypename)
	}
}

func TestDhcpcdExternal(t *testing.T) {
	c := Dhcpcd{}
	if c.External() {
		t.Error("expected External() = false")
	}
}

func TestDhcpcdString(t *testing.T) {
	c := Dhcpcd{AdapterIfName: "eth0", AdapterLL: "eth0"}
	if s := c.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

func TestDhcpcdDependencies(t *testing.T) {
	c := Dhcpcd{AdapterIfName: "eth0"}
	deps := c.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].RequiredItem.ItemType != AdapterTypename {
		t.Errorf("dep type: got %q, want %q", deps[0].RequiredItem.ItemType, AdapterTypename)
	}
	if deps[0].RequiredItem.ItemName != "eth0" {
		t.Errorf("dep name: got %q, want %q", deps[0].RequiredItem.ItemName, "eth0")
	}
}

// --- NetIO ---

func TestNetIOName(t *testing.T) {
	n := NetIO{IfName: "eth0", LogicalLabel: "eth0-label"}
	if got := n.Name(); got != "eth0" {
		t.Errorf("got %q, want %q", got, "eth0")
	}
}

func TestNetIOLabel(t *testing.T) {
	n := NetIO{LogicalLabel: "eth0-label"}
	if got := n.Label(); got != "eth0-label (IO)" {
		t.Errorf("got %q", got)
	}
}

func TestNetIOType(t *testing.T) {
	n := NetIO{}
	if got := n.Type(); got != NetIOTypename {
		t.Errorf("got %q, want %q", got, NetIOTypename)
	}
}

func TestNetIOExternal(t *testing.T) {
	n := NetIO{}
	if !n.External() {
		t.Error("expected External() = true")
	}
}

func TestNetIOEqual(t *testing.T) {
	n := NetIO{IfName: "eth0"}
	// Equal always returns true regardless of the argument.
	if !n.Equal(NetIO{IfName: "eth1"}) {
		t.Error("NetIO.Equal should always return true")
	}
	if !n.Equal(ResolvConf{}) {
		t.Error("NetIO.Equal should always return true for any item type")
	}
}

func TestNetIODependencies(t *testing.T) {
	n := NetIO{}
	if deps := n.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestNetIOString(t *testing.T) {
	n := NetIO{IfName: "eth0", LogicalLabel: "eth0-label"}
	if s := n.String(); s == "" {
		t.Error("expected non-empty string")
	}
}

// --- ResolvConf ---

func TestResolvConfName(t *testing.T) {
	r := ResolvConf{}
	if got := r.Name(); got != resolvConfFilename {
		t.Errorf("got %q, want %q", got, resolvConfFilename)
	}
}

func TestResolvConfLabel(t *testing.T) {
	r := ResolvConf{}
	if got := r.Label(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestResolvConfType(t *testing.T) {
	r := ResolvConf{}
	if got := r.Type(); got != ResolvConfTypename {
		t.Errorf("got %q, want %q", got, ResolvConfTypename)
	}
}

func TestResolvConfExternal(t *testing.T) {
	r := ResolvConf{}
	if r.External() {
		t.Error("expected External() = false")
	}
}

func TestResolvConfDependencies(t *testing.T) {
	r := ResolvConf{}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestResolvConfEqual(t *testing.T) {
	dns1 := net.ParseIP("8.8.8.8")
	dns2 := net.ParseIP("1.1.1.1")
	r1 := ResolvConf{DNSServers: map[string][]net.IP{"eth0": {dns1}}}
	r2Same := ResolvConf{DNSServers: map[string][]net.IP{"eth0": {dns1}}}
	r3Diff := ResolvConf{DNSServers: map[string][]net.IP{"eth0": {dns2}}}
	r4Empty := ResolvConf{}
	tests := []struct {
		name  string
		r     ResolvConf
		other dg.Item
		want  bool
	}{
		{"identical", r1, r2Same, true},
		{"different IP", r1, r3Diff, false},
		{"both empty", r4Empty, r4Empty, true},
		{"one empty", r1, r4Empty, false},
		{"wrong type", r1, NetIO{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvConfString(t *testing.T) {
	r := ResolvConf{}
	if got := r.String(); got != "resolv.conf with empty content" {
		t.Errorf("empty: got %q", got)
	}
	r2 := ResolvConf{DNSServers: map[string][]net.IP{"eth0": {net.ParseIP("8.8.8.8")}}}
	if s := r2.String(); s == "" || s == "resolv.conf with empty content" {
		t.Errorf("non-empty: unexpected %q", s)
	}
}

// --- SSHAuthKeys ---

func TestSSHAuthKeysName(t *testing.T) {
	s := SSHAuthKeys{}
	if got := s.Name(); got != authKeysFilename {
		t.Errorf("got %q, want %q", got, authKeysFilename)
	}
}

func TestSSHAuthKeysLabel(t *testing.T) {
	s := SSHAuthKeys{}
	if got := s.Label(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestSSHAuthKeysType(t *testing.T) {
	s := SSHAuthKeys{}
	if got := s.Type(); got != SSHAuthKeysTypename {
		t.Errorf("got %q, want %q", got, SSHAuthKeysTypename)
	}
}

func TestSSHAuthKeysExternal(t *testing.T) {
	s := SSHAuthKeys{}
	if s.External() {
		t.Error("expected External() = false")
	}
}

func TestSSHAuthKeysDependencies(t *testing.T) {
	s := SSHAuthKeys{}
	if deps := s.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestSSHAuthKeysEqual(t *testing.T) {
	s1 := SSHAuthKeys{Keys: "ssh-rsa AAAA..."}
	s2Same := SSHAuthKeys{Keys: "ssh-rsa AAAA..."}
	s3Diff := SSHAuthKeys{Keys: "ssh-ed25519 BBBB..."}
	s4Empty := SSHAuthKeys{}
	tests := []struct {
		name  string
		s     SSHAuthKeys
		other dg.Item
		want  bool
	}{
		{"same keys", s1, s2Same, true},
		{"different keys", s1, s3Diff, false},
		{"both empty", s4Empty, s4Empty, true},
		{"wrong type", s1, ResolvConf{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSSHAuthKeysString(t *testing.T) {
	s := SSHAuthKeys{Keys: "ssh-rsa AAAA..."}
	if str := s.String(); str == "" {
		t.Error("expected non-empty string")
	}
}

// --- Wwan ---

func TestWwanName(t *testing.T) {
	w := Wwan{}
	if got := w.Name(); got != pubsubWwanKey {
		t.Errorf("got %q, want %q", got, pubsubWwanKey)
	}
}

func TestWwanLabel(t *testing.T) {
	w := Wwan{}
	if got := w.Label(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestWwanType(t *testing.T) {
	w := Wwan{}
	if got := w.Type(); got != WwanTypename {
		t.Errorf("got %q, want %q", got, WwanTypename)
	}
}

func TestWwanExternal(t *testing.T) {
	w := Wwan{}
	if w.External() {
		t.Error("expected External() = false")
	}
}

func TestWwanDependencies(t *testing.T) {
	w := Wwan{}
	if deps := w.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestWwanEqual(t *testing.T) {
	w1 := Wwan{Config: types.WwanConfig{}}
	w2 := Wwan{Config: types.WwanConfig{}}
	tests := []struct {
		name  string
		w     Wwan
		other dg.Item
		want  bool
	}{
		{"equal empty configs", w1, w2, true},
		{"wrong type", w1, ResolvConf{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.Equal(tc.other); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWwanString(t *testing.T) {
	w := Wwan{}
	if s := w.String(); s == "" {
		t.Error("expected non-empty string")
	}
}
