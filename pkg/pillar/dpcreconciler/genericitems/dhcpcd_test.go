// Copyright (c) 2022-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems_test

import (
	"net"
	"testing"

	configitems "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

func TestDhcpcdEqual(t *testing.T) {
	t.Parallel()
	type test struct {
		name     string
		item1    configitems.Dhcpcd
		item2    configitems.Dhcpcd
		expEqual bool
	}
	var tests = []test{
		{
			name: "DHCP client for IPv4 only",
			item1: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeClient,
					AddrSubnet: "192.168.1.44/24",          // irrelevant
					Gateway:    net.ParseIP("192.168.1.1"), // irrelevant
					DomainName: "mydomain",                 // irrelevant
					NTPServers: []string{"192.168.1.1"},    // irrelevant
					Type:       types.NetworkTypeIpv4Only,  // must match
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeIpv4Only, // must match
				},
			},
			expEqual: true,
		},
		{
			name: "DHCP client with effectively equivalent IP types",
			item1: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeNOOP, // sometimes we get this in override.json
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeIPv4, // effectively equivalent to NetworkTypeNOOP
				},
			},
			expEqual: true,
		},
		{
			name: "DHCP client with effectively different IP types",
			item1: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeIPv4,
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeIpv4Only, // differs in --ipv4only arg
				},
			},
			expEqual: false,
		},
		{
			name: "DHCP client with disabled default route",
			item1: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:    types.DhcpTypeClient,
					Gateway: net.ParseIP("0.0.0.0"), // default route is disabled

				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DhcpTypeClient,
					// default route is enabled
				},
			},
			expEqual: false,
		},
		{
			name: "equivalent static IP config",
			item1: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeStatic,
					AddrSubnet: "192.168.1.44/24",
					DomainName: "mydomain",
					NTPServers: []string{"192.168.1.1"},
					DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
					Type:       types.NetworkTypeIpv4Only, // irrelevant
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeStatic,
					AddrSubnet: "192.168.1.44/24",
					DomainName: "mydomain",
					NTPServers: []string{"192.168.1.1"},
					DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
					Type:       types.NetworkTypeIPv4, // irrelevant
				},
			},
			expEqual: true,
		},
		{
			name: "different statically configured DNS servers",
			item1: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeStatic,
					AddrSubnet: "192.168.1.44/24",
					DomainName: "mydomain",
					NTPServers: []string{"192.168.1.1"},
					DNSServers: []net.IP{net.ParseIP("8.8.8.8")}, // does not match
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeStatic,
					AddrSubnet: "192.168.1.44/24",
					DomainName: "mydomain",
					NTPServers: []string{"192.168.1.1"},
					DNSServers: []net.IP{net.ParseIP("1.1.1.1")}, // does not match
				},
			},
			expEqual: false,
		},
	}
	for _, test := range tests {
		if test.item1.Equal(test.item2) != test.expEqual {
			t.Errorf("TEST CASE \"%s\" FAILED - Equal() returned: %t, expected: %t",
				test.name, test.item1.Equal(test.item2), test.expEqual)
		}
	}
}

func TestDhcpcdArgs(t *testing.T) {
	t.Parallel()
	type test struct {
		name    string
		config  types.DhcpConfig
		expOp   string
		expArgs []string
	}
	var tests = []test{
		{
			name: "DHCP client for IPv4 only",
			config: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIpv4Only,
			},
			expOp:   "--request",
			expArgs: []string{"-f", "/dhcpcd.conf", "--noipv4ll", "--ipv4only", "-b", "-t", "0"},
		},
		{
			name: "DHCP client for IPv4 only with zero gateway",
			config: types.DhcpConfig{
				Dhcp:    types.DhcpTypeClient,
				Type:    types.NetworkTypeIpv4Only,
				Gateway: net.IP{0, 0, 0, 0},
			},
			expOp:   "--request",
			expArgs: []string{"-f", "/dhcpcd.conf", "--noipv4ll", "--ipv4only", "-b", "-t", "0", "--nogateway"},
		},
		{
			name: "DHCP client for IPv6 only",
			config: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIpv6Only,
			},
			expOp:   "--request",
			expArgs: []string{"-f", "/dhcpcd.conf", "--ipv6only", "-b", "-t", "0"},
		},
		{
			name: "DHCP client for dual stack",
			config: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeDualStack,
			},
			expOp:   "--request",
			expArgs: []string{"-f", "/dhcpcd.conf", "--noipv4ll", "-b", "-t", "0"},
		},
		{
			name: "Static IPv4 config",
			config: types.DhcpConfig{
				Dhcp:       types.DhcpTypeStatic,
				AddrSubnet: "192.168.1.44/24",
				Gateway:    net.IP{192, 168, 1, 1},
				DomainName: "mydomain",
				NTPServers: []string{"192.168.1.1", "10.10.12.13"},
				DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
				Type:       types.NetworkTypeIpv4Only, // irrelevant
			},
			expOp: "--static",
			expArgs: []string{"ip_address=192.168.1.44/24", "--static", "routers=192.168.1.1",
				"--static", "domain_name=mydomain", "--static", "domain_name_servers=8.8.8.8",
				"--static", "ntp_servers=192.168.1.1", "--static", "ntp_servers=10.10.12.13",
				"-f", "/dhcpcd.conf", "-b", "-t", "0"},
		},
		{
			name: "Static IPv4 config with unspecified gateway",
			config: types.DhcpConfig{
				Dhcp:       types.DhcpTypeStatic,
				AddrSubnet: "192.168.1.44/24",
				DomainName: "mydomain",
				NTPServers: []string{"192.168.1.1", "10.10.12.13"},
				DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
				Type:       types.NetworkTypeIpv4Only, // irrelevant
			},
			expOp: "--static",
			expArgs: []string{"ip_address=192.168.1.44/24",
				"--static", "domain_name=mydomain", "--static", "domain_name_servers=8.8.8.8",
				"--static", "ntp_servers=192.168.1.1", "--static", "ntp_servers=10.10.12.13",
				"-f", "/dhcpcd.conf", "-b", "-t", "0", "--nogateway"},
		},
	}
	configurator := configitems.DhcpcdConfigurator{}
	for _, test := range tests {
		op, args := configurator.DhcpcdArgs(test.config)
		if op != test.expOp || !generics.EqualLists(args, test.expArgs) {
			t.Errorf("TEST CASE \"%s\" FAILED - DhcpcdArgs() returned: %s %v, "+
				"expected: %s %v", test.name, op, args, test.expOp, test.expArgs)
		}
	}
}
