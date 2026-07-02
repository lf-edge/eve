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

func TestAdapterAddrsDependencies(t *testing.T) {
	a := AdapterAddrs{}
	if deps := a.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
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

// --- Dhcpcd ---

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

func TestResolvConfDependencies(t *testing.T) {
	r := ResolvConf{}
	if deps := r.Dependencies(); deps != nil {
		t.Errorf("expected nil deps, got %v", deps)
	}
}

func TestResolvConfEqual(t *testing.T) {
	r1 := ResolvConf{SearchDomains: []string{"local", "test"}}
	r2Same := ResolvConf{SearchDomains: []string{"test", "local"}}
	r3Diff := ResolvConf{SearchDomains: []string{"local"}}
	r4Empty := ResolvConf{}
	tests := []struct {
		name  string
		r     ResolvConf
		other dg.Item
		want  bool
	}{
		{"identical", r1, r2Same, true},
		{"different search domains", r1, r3Diff, false},
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
