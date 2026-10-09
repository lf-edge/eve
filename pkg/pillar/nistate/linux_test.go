// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nistate

import (
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestSetExternalDHCPv4ReplacesPreviousLease(t *testing.T) {
	vif := &vifInfo{ipv4Addrs: []detectedAddr{
		{
			AssignedAddr: types.AssignedAddr{
				Address:    net.ParseIP("192.168.1.189"),
				AssignedBy: types.AddressSourceExternalDHCP,
			},
			validUntil: time.Now().Add(time.Hour),
		},
		{
			AssignedAddr: types.AssignedAddr{
				Address:    net.ParseIP("192.168.1.10"),
				AssignedBy: types.AddressSourceStatic,
			},
		},
	}}

	update := vif.setExternalDHCPv4(net.ParseIP("192.168.1.190"),
		time.Now().Add(2*time.Hour))
	if update == nil {
		t.Fatal("replacing an external DHCPv4 lease did not produce an update")
	}
	if update.Prev.hasIPv4("192.168.1.190") {
		t.Fatalf("new lease unexpectedly present in previous addresses: %+v", update.Prev)
	}
	if update.New.hasIPv4("192.168.1.189") {
		t.Fatalf("old external DHCPv4 lease was retained: %+v", update.New)
	}
	if !update.New.hasIPv4("192.168.1.190") {
		t.Fatalf("new external DHCPv4 lease was not stored: %+v", update.New)
	}
	if !update.New.hasIPv4("192.168.1.10") {
		t.Fatalf("static IPv4 address was removed with the old DHCP lease: %+v", update.New)
	}
}

func TestSetExternalDHCPv4RenewalDoesNotPublishChange(t *testing.T) {
	oldExpiry := time.Now().Add(time.Hour)
	newExpiry := oldExpiry.Add(time.Hour)
	vif := &vifInfo{ipv4Addrs: []detectedAddr{{
		AssignedAddr: types.AssignedAddr{
			Address:    net.ParseIP("192.168.1.190"),
			AssignedBy: types.AddressSourceExternalDHCP,
		},
		validUntil: oldExpiry,
	}}}

	if update := vif.setExternalDHCPv4(net.ParseIP("192.168.1.190"), newExpiry); update != nil {
		t.Fatalf("renewal of the same DHCPv4 address produced an update: %+v", update)
	}
	if !vif.ipv4Addrs[0].validUntil.Equal(newExpiry) {
		t.Fatalf("renewal expiry was not refreshed: got %v, want %v",
			vif.ipv4Addrs[0].validUntil, newExpiry)
	}
}

func (addrs VIFAddrs) hasIPv4(want string) bool {
	wantIP := net.ParseIP(want)
	for _, addr := range addrs.IPv4Addrs {
		if addr.Address.Equal(wantIP) {
			return true
		}
	}
	return false
}
