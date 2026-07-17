// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPort(t *testing.T) {
	dns := DeviceNetworkStatus{
		Ports: []NetworkPortStatus{
			// The physical NIC the model labels "enp6s0" but which the kernel
			// named "eth0" (predictable naming is off); its PCI address is
			// recorded so it can be matched independent of the name.
			{IfName: "eth0", PciLong: "0000:06:00.0"},
			// A port with no PCI address recorded (e.g. a USB NIC), used to
			// check that an empty pciLong query does not match it.
			{IfName: "wlan0"},
			// A port whose interface name is not yet known, used to check that
			// an empty ifname query does not spuriously match it.
			{IfName: "", PciLong: ""},
		},
	}

	tests := []struct {
		name    string
		ifname  string
		pciLong string
		want    bool
	}{
		{"interface name match", "eth0", "", true},
		{"no match", "eth2", "", false},
		// The regression this guards: the model calls the port "enp6s0" but
		// the live port is named "eth0"; matching on the PCI address still
		// recognizes it as a port so it is not reserved to pciback.
		{"pci match despite ifname mismatch", "enp6s0", "0000:06:00.0", true},
		{"ifname match wins even with unknown pci", "eth0", "0000:99:00.0", true},
		{"neither ifname nor pci match", "enp7s0", "0000:07:00.0", false},
		// An empty pciLong must never match a port that also has no PCI
		// recorded, otherwise every unknown device would look like a port.
		{"empty pci does not match empty-pci port", "eth9", "", false},
		// A non-network device (empty/irrelevant ifname) still recognized when
		// its PCI address is in use as a port.
		{"empty ifname matches by pci only", "", "0000:06:00.0", true},
		// An empty ifname must not match the port with an unknown interface
		// name, nor must empty+empty match anything.
		{"empty ifname does not match empty-ifname port", "", "0000:aa:00.0", false},
		{"empty ifname and empty pci never match", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPort(dns, tt.ifname, tt.pciLong))
		})
	}
}
