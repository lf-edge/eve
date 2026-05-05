// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmonitor

import (
	"net"
	"testing"
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
