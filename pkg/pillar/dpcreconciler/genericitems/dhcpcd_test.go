package genericitems_test

import (
	"net"
	"testing"

	configitems "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
					NTPServer:  net.ParseIP("192.168.1.1"), // irrelevant
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
					NTPServer:  net.ParseIP("192.168.1.1"),
					DNSServers: []net.IP{net.ParseIP("8.8.8.8")},
					Type:       types.NetworkTypeIpv4Only, // irrelevant
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeStatic,
					AddrSubnet: "192.168.1.44/24",
					DomainName: "mydomain",
					NTPServer:  net.ParseIP("192.168.1.1"),
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
					NTPServer:  net.ParseIP("192.168.1.1"),
					DNSServers: []net.IP{net.ParseIP("8.8.8.8")}, // does not match
				},
			},
			item2: configitems.Dhcpcd{
				DhcpConfig: types.DhcpConfig{
					Dhcp:       types.DhcpTypeStatic,
					AddrSubnet: "192.168.1.44/24",
					DomainName: "mydomain",
					NTPServer:  net.ParseIP("192.168.1.1"),
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
