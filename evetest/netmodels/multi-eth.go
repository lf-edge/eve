// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmodels

import (
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// TwoMgmtPorts is a network model with two ethernet ports, each on its own
// bridge and network with DHCP and access to the controller. Both are intended
// to be used as management ports on the EVE side.
var TwoMgmtPorts = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
		{
			LogicalLabel: "eth1",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
		},
		{
			LogicalLabel: "bridge1",
			Ports:        []string{"eth1"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.20.0/24",
				GwIp:   "172.20.20.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server0"},
					},
				},
			},
		},
		{
			LogicalLabel: "network1",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.21.0/24",
				GwIp:   "172.20.21.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server1"},
					},
				},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server0",
					Fqdn:         "dns-server0.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server1",
					Fqdn:         "dns-server1.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.17.0/24",
						Ip:     "10.16.17.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
		},
	},
}

// TwoMgmtPortsOneBridge is a network model with two ethernet ports on a single
// bridge and network with DHCP and access to the controller. It is intended
// for bond (link aggregation) tests where both ports must reach the same network.
var TwoMgmtPortsOneBridge = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
		{
			LogicalLabel: "eth1",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0", "eth1"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.20.0/24",
				GwIp:   "172.20.20.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
		},
	},
}

// BondWithVLANs is a network model with three Ethernet ports: eth0 and eth1
// aggregated by an SDN-side LACP (802.3ad) bond, and eth2 as a standalone trunk
// port. A single bridge spans the bond and eth2, carrying three VLAN-tagged
// networks:
//   - VLAN 10 (172.22.10.0/24): management VLAN, controller-reachable.
//   - VLAN 20 (172.22.20.0/24): application VLAN; http-server-20.test
//     (10.20.20.70) is reachable exclusively from VLAN 20.
//   - VLAN 30 (172.22.30.0/24): application VLAN; http-server-30.test
//     (10.30.30.70) is reachable exclusively from VLAN 30.
//
// A shared DNS server (10.16.16.25) is reachable from all three VLANs and
// resolves the controller hostname as well as both HTTP server FQDNs.
// There is no cross-VLAN routing: the three routers are fully isolated.
var BondWithVLANs = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
		{LogicalLabel: "eth2", AdminUp: true},
	},
	Bonds: []*api.Bond{
		{
			LogicalLabel: "sdn-bond0",
			Ports:        []string{"eth0", "eth1"},
			Mode:         api.BondMode_BOND_MODE_802_3AD,
			LacpRate:     api.LacpRate_LACP_RATE_FAST,
			MiiMonitor: &api.BondMIIMonitor{
				Enabled:  true,
				Interval: 100,
			},
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Bonds:        []string{"sdn-bond0"},
			Ports:        []string{"eth2"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network-10",
			Bridge:       "bridge0",
			VlanId:       10,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.10.0/24",
				GwIp:   "172.22.10.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "172.22.10.10", ToIp: "172.22.10.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server"},
			},
		},
		{
			LogicalLabel: "network-20",
			Bridge:       "bridge0",
			VlanId:       20,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.20.0/24",
				GwIp:   "172.22.20.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "172.22.20.10", ToIp: "172.22.20.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"dns-server", "http-server-20"},
			},
		},
		{
			LogicalLabel: "network-30",
			Bridge:       "bridge0",
			VlanId:       30,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.30.0/24",
				GwIp:   "172.22.30.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "172.22.30.10", ToIp: "172.22.30.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"dns-server", "http-server-30"},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-20",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-20",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-30",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-30",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"1.1.1.1", "8.8.8.8"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-20",
					Fqdn:         "http-server-20.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.20.20.0/24",
						Ip:     "10.20.20.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from HTTP server for VLAN 20\n",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-30",
					Fqdn:         "http-server-30.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.30.30.0/24",
						Ip:     "10.30.30.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from HTTP server for VLAN 30\n",
					},
				},
			},
		},
	},
}

// TwoMgmtPortsWithLACPBond is a network model with two ethernet ports aggregated
// by an SDN-side LACP (802.3ad) bond. The bond is attached to a bridge with
// a DHCP network and access to the controller. It is intended for LACP bond
// tests where the SDN side must participate in LACP negotiation with EVE.
var TwoMgmtPortsWithLACPBond = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
		{
			LogicalLabel: "eth1",
			AdminUp:      true,
		},
	},
	Bonds: []*api.Bond{
		{
			LogicalLabel: "sdn-bond0",
			Ports:        []string{"eth0", "eth1"},
			Mode:         api.BondMode_BOND_MODE_802_3AD,
			LacpRate:     api.LacpRate_LACP_RATE_FAST,
			MiiMonitor: &api.BondMIIMonitor{
				Enabled:  true,
				Interval: 100,
			},
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Bonds:        []string{"sdn-bond0"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.20.0/24",
				GwIp:   "172.20.20.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
		},
	},
}

// ManyDNSServers is a network model with four ethernet ports, each on its own
// bridge and network with DHCP and access to the controller. All four are
// intended to be used as management ports on the EVE side.
//
// DNS server layout (bad-dns3 has no UpstreamServers so it resolves nothing;
// all other servers forward unknown names to 8.8.8.8/1.1.1.1):
//
//   - network0 (eth0): DHCP advertises dhcp-dns0 (10.35.0.25), which knows
//     the controller and http-server1.test. A static server static-dns0
//     (10.35.5.25) with the same knowledge is also available for device-side
//     static DNS configuration.
//   - network1 (eth1): DHCP advertises two servers, dhcp-dns1a (10.35.1.25)
//     and dhcp-dns1b (10.35.2.25), both knowing the controller and
//     http-server1.test. A static server static-dns1 (10.35.6.25) with the
//     same knowledge is also available.
//   - network2 (eth2): DHCP advertises dhcp-dns2 (10.35.3.25), which knows
//     the controller and http-server2.test. A static server static-dns2
//     (10.35.7.25) with the same knowledge is also available.
//   - network3 (eth3): DHCP advertises bad-dns3 (10.35.4.25), which has no
//     static entries and no upstream — it resolves nothing.
//
// Two HTTP server endpoints are provided: http-server1.test (10.36.0.25) and
// http-server2.test (10.36.1.25), reachable from any port via SDN routing.
var ManyDNSServers = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
		{LogicalLabel: "eth2", AdminUp: true},
		{LogicalLabel: "eth3", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
		{LogicalLabel: "bridge1", Ports: []string{"eth1"}},
		{LogicalLabel: "bridge2", Ports: []string{"eth2"}},
		{LogicalLabel: "bridge3", Ports: []string{"eth3"}},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.30.0.0/24",
				GwIp:   "172.30.0.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dhcp-dns0"},
					},
				},
			},
		},
		{
			LogicalLabel: "network1",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.30.1.0/24",
				GwIp:   "172.30.1.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dhcp-dns1a", "dhcp-dns1b"},
					},
				},
			},
		},
		{
			LogicalLabel: "network2",
			Bridge:       "bridge2",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.30.2.0/24",
				GwIp:   "172.30.2.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dhcp-dns2"},
					},
				},
			},
		},
		{
			LogicalLabel: "network3",
			Bridge:       "bridge3",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.30.3.0/24",
				GwIp:   "172.30.3.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"bad-dns3"},
					},
				},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dhcp-dns0",
					Fqdn:         "dhcp-dns0.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.0.0/24",
						Ip:     "10.35.0.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dhcp-dns1a",
					Fqdn:         "dhcp-dns1a.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.1.0/24",
						Ip:     "10.35.1.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dhcp-dns1b",
					Fqdn:         "dhcp-dns1b.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.2.0/24",
						Ip:     "10.35.2.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dhcp-dns2",
					Fqdn:         "dhcp-dns2.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.3.0/24",
						Ip:     "10.35.3.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server2",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server2",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				// bad-dns3 has no static entries and no upstream servers — resolves nothing.
				Endpoint: &api.Endpoint{
					LogicalLabel: "bad-dns3",
					Fqdn:         "bad-dns3.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.4.0/24",
						Ip:     "10.35.4.25",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "static-dns0",
					Fqdn:         "static-dns0.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.5.0/24",
						Ip:     "10.35.5.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "static-dns1",
					Fqdn:         "static-dns1.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.6.0/24",
						Ip:     "10.35.6.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "static-dns2",
					Fqdn:         "static-dns2.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.35.7.0/24",
						Ip:     "10.35.7.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server2",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server2",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server1",
					Fqdn:         "http-server1.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.36.0.0/24",
						Ip:     "10.36.0.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server2",
					Fqdn:         "http-server2.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.36.1.0/24",
						Ip:     "10.36.1.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
		},
	},
}

// FourPortsWithSTPBridge is a network model with four ethernet ports across
// two L2 domains:
//   - eth0 — its own management bridge (bridge0) with DHCP (172.20.20.0/24),
//     a DNS server, and access to the controller and http-server.test.
//   - eth1, eth2 — both on a single STP-enabled bridge (bridge1, WithStp=true),
//     forming redundant L2 paths. An SDN router provides DHCP (10.51.0.0/24,
//     pool .2–.150) and routes to http-server.test.
//   - eth3 — leaf port on a separate SDN bridge (bridge2), but expected to be
//     bridged with eth1+eth2 inside EVE. An HTTP server (leaf-httpserver.test)
//     is directly L2-connected to bridge2, and therefore uses an IP from the
//     same subnet as bridge1 (10.51.0.0/24).
var FourPortsWithSTPBridge = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
		{LogicalLabel: "eth2", AdminUp: true},
		{LogicalLabel: "eth3", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
		{LogicalLabel: "bridge1", Ports: []string{"eth1", "eth2"}, WithStp: true},
		{LogicalLabel: "bridge2", Ports: []string{"eth3"}}, // leaf bridge, no STP
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "mgmt-network",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.20.0/24",
				GwIp:   "172.20.20.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
		},
		{
			LogicalLabel: "app-network",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.51.0.0/24",
				GwIp:   "10.51.0.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					// Restrict the pool to .2–.150 so that the static IP of
					// leaf-httpserver (10.51.0.200) is safely outside.
					IpRange: &api.IPRange{
						FromIp: "10.51.0.2",
						ToIp:   "10.51.0.150",
					},
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
		},
		// bridge2 (eth3) has no network — the leaf-httpserver connects directly at L2.
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "leaf-httpserver",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "leaf-httpserver",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
			{
				// Directly L2-connected to bridge2 (eth3 leaf) — no router between it
				// and EVE. Its IP (10.51.0.200) is inside the subnet of app-network
				// (bridge1) because the expectation is that eth1, eth2 and eth3 are
				// all bridged together inside EVE.
				Endpoint: &api.Endpoint{
					LogicalLabel: "leaf-httpserver",
					Fqdn:         "leaf-httpserver.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.51.0.0/24",
						Ip:     "10.51.0.200",
					},
					DirectL2Connect: &api.DirectL2EpConnect{
						Bridge: "bridge2",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from leaf!",
					},
				},
			},
		},
	},
}

// ApplicationVLANs is a network model with four ethernet ports where the
// management path is untagged and the application data paths use VLANs:
//   - eth0 -> bridge0 -> plain management network (172.22.12.0/24, DHCP,
//     controller access). No VLANs on this path.
//   - eth1 -> bridge1 -> SDN router serving two VLAN-tagged application
//     networks: VLAN 100 (10.203.100.0/24) and VLAN 200 (10.203.200.0/24).
//     eth1 is the TRUNK side (carries both VLANs tagged toward the router).
//   - eth2 -> bridge2 -> HTTP server "http-server-100.test" (10.203.100.10)
//     directly L2-connected (no router). eth2 is the ACCESS side for VLAN 100.
//   - eth3 -> bridge3 -> HTTP server "http-server-200.test" (10.203.200.10)
//     directly L2-connected. eth3 is the ACCESS side for VLAN 200.
//
// The DNS server (10.16.16.25) resolves the controller hostname and both HTTP
// server FQDNs, with upstream forwarding for everything else.
var ApplicationVLANs = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
		{LogicalLabel: "eth2", AdminUp: true},
		{LogicalLabel: "eth3", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
		{LogicalLabel: "bridge1", Ports: []string{"eth1"}},
		{LogicalLabel: "bridge2", Ports: []string{"eth2"}}, // direct L2: http-server-100
		{LogicalLabel: "bridge3", Ports: []string{"eth3"}}, // direct L2: http-server-200
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "mgmt-network",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.12.0/24",
				GwIp:   "172.22.12.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					IpRange: &api.IPRange{
						FromIp: "172.22.12.10",
						ToIp:   "172.22.12.20",
					},
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
		},
		{
			// VLAN 100 network: served via eth1 (trunk) by the SDN router.
			LogicalLabel: "vlan100-network",
			Bridge:       "bridge1",
			VlanId:       100,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.203.100.0/24",
				GwIp:   "10.203.100.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					IpRange: &api.IPRange{
						FromIp: "10.203.100.100",
						ToIp:   "10.203.100.200",
					},
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server"},
			},
		},
		{
			// VLAN 200 network: served via eth1 (trunk) by the SDN router.
			LogicalLabel: "vlan200-network",
			Bridge:       "bridge1",
			VlanId:       200,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.203.200.0/24",
				GwIp:   "10.203.200.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					IpRange: &api.IPRange{
						FromIp: "10.203.200.100",
						ToIp:   "10.203.200.200",
					},
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server"},
			},
		},
		// bridge2 and bridge3 have no SDN networks — HTTP servers connect directly at L2.
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-100",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-100",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-200",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-200",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"1.1.1.1", "8.8.8.8"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				// Directly L2-connected to bridge2 (eth2 access port for VLAN 100).
				// IP is in the VLAN 100 subnet so that it is reachable from VLAN-100 apps.
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-100",
					Fqdn:         "http-server-100.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.203.100.0/24",
						Ip:     "10.203.100.10",
					},
					DirectL2Connect: &api.DirectL2EpConnect{
						Bridge: "bridge2",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from HTTP server for VLAN 100\n",
					},
				},
			},
			{
				// Directly L2-connected to bridge3 (eth3 access port for VLAN 200).
				// IP is in the VLAN 200 subnet so that it is reachable from VLAN-200 apps.
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-200",
					Fqdn:         "http-server-200.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.203.200.0/24",
						Ip:     "10.203.200.10",
					},
					DirectL2Connect: &api.DirectL2EpConnect{
						Bridge: "bridge3",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from HTTP server for VLAN 200\n",
					},
				},
			},
		},
	},
}

// ThreeIsolatedPorts is a network model with three ethernet ports, each on its
// own bridge and network, with strictly isolated SDN-side routing:
//
//   - eth0 -> bridge0 -> 172.22.12.0/24 (DHCP, controller-reachable,
//     http-server-0.test at 10.20.20.70 and dns-server at 10.16.16.25 reachable).
//   - eth1 -> bridge1 -> 192.168.55.0/24 (no DHCP, http-server-1.test at
//     10.21.21.70 reachable only).
//   - eth2 -> bridge2 -> 10.140.2.0/24 (DHCP without router option,
//     http-server-2.test at 10.22.22.70 reachable only).
//
// The shared DNS server (10.16.16.25) is reachable only via eth0 and resolves
// the controller hostname plus all three HTTP server FQDNs.
var ThreeIsolatedPorts = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
		{LogicalLabel: "eth2", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
		{LogicalLabel: "bridge1", Ports: []string{"eth1"}},
		{LogicalLabel: "bridge2", Ports: []string{"eth2"}},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network-eth0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.12.0/24",
				GwIp:   "172.22.12.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "172.22.12.10", ToIp: "172.22.12.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server", "http-server-0"},
			},
		},
		{
			// No DHCP: EVE is expected to configure a static IP on this port.
			LogicalLabel: "network-eth1",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "192.168.55.0/24",
				GwIp:   "192.168.55.1",
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"http-server-1"},
			},
		},
		{
			// DHCP is enabled but the router option is suppressed (WithoutDefaultRoute).
			LogicalLabel: "network-eth2",
			Bridge:       "bridge2",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.140.2.0/24",
				GwIp:   "10.140.2.1",
				Dhcp: &api.DHCP{
					Enable:              true,
					IpRange:             &api.IPRange{FromIp: "10.140.2.10", ToIp: "10.140.2.20"},
					DomainName:          "test",
					WithoutDefaultRoute: true,
				},
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"http-server-2"},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-0",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-0",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-2",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-2",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-0",
					Fqdn:         "http-server-0.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.20.20.0/24",
						Ip:     "10.20.20.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from HTTP server 0!\n",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-1",
					Fqdn:         "http-server-1.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.21.21.0/24",
						Ip:     "10.21.21.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from HTTP server 1!\n",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-2",
					Fqdn:         "http-server-2.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.22.22.0/24",
						Ip:     "10.22.22.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from HTTP server 2!\n",
					},
				},
			},
		},
	},
}

// FourPortsMixedAccess is a network model with four ethernet ports offering
// mixed levels of Internet and server reachability:
//
//   - eth0 -> bridge0 -> 172.22.10.0/24 (DHCP, controller-reachable;
//     dns-server at 10.16.16.25 and http-server.test at 10.88.88.70 reachable).
//   - eth1 -> bridge1 -> 172.28.20.0/24 (no DHCP, no controller path;
//     only dns-server reachable, http-server NOT reachable from this port).
//   - eth2 -> bridge2 -> 192.168.30.0/24 (DHCP, no controller path;
//     dns-server and http-server.test reachable).
//   - eth3 -> bridge3 -> 10.40.40.0/24 (no DHCP, controller-reachable;
//     dns-server and http-server.test reachable).
//
// A shared DNS server (10.16.16.25) is reachable from all four ports and
// resolves the controller hostname and the HTTP server FQDN.
// The HTTP server (http-server.test, 10.88.88.70) is reachable from eth0,
// eth2, and eth3 only; eth1 has no route to it.
var FourPortsMixedAccess = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
		{LogicalLabel: "eth2", AdminUp: true},
		{LogicalLabel: "eth3", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
		{LogicalLabel: "bridge1", Ports: []string{"eth1"}},
		{LogicalLabel: "bridge2", Ports: []string{"eth2"}},
		{LogicalLabel: "bridge3", Ports: []string{"eth3"}},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network-eth0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.10.0/24",
				GwIp:   "172.22.10.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "172.22.10.10", ToIp: "172.22.10.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server", "http-server"},
			},
		},
		{
			// No DHCP: EVE is expected to configure a static IP on this port.
			// No route to the HTTP server from this port.
			LogicalLabel: "network-eth1",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.28.20.0/24",
				GwIp:   "172.28.20.1",
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"dns-server"},
			},
		},
		{
			LogicalLabel: "network-eth2",
			Bridge:       "bridge2",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "192.168.30.0/24",
				GwIp:   "192.168.30.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "192.168.30.10", ToIp: "192.168.30.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"dns-server", "http-server"},
			},
		},
		{
			// No DHCP: EVE is expected to configure a static IP on this port.
			LogicalLabel: "network-eth3",
			Bridge:       "bridge3",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.40.40.0/24",
				GwIp:   "10.40.40.1",
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server", "http-server"},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.88.88.0/24",
						Ip:     "10.88.88.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from HTTP server!\n",
					},
				},
			},
		},
	},
}

// AppGatewayTopology is a two-port network model for the "gateway app" routing pattern.
//
//   - eth0 (172.22.12.0/24): management port, controller-reachable, DHCP.
//     Provides access to dns-server (10.16.16.25), http-server-1.test (10.20.20.70)
//     and the controller.
//   - eth1 (10.203.10.0/24): application port used by a gateway app as its WAN egress
//     (Switch NI). DHCP with a static reservation: MAC 02:16:3e:01:00:00 → 10.203.10.150.
//     The gateway app MUST configure its WAN VIF (the one attached to this Switch NI)
//     with MAC address 02:16:3e:01:00:00 to receive the deterministic IP 10.203.10.150.
//     This address is required for the RoutesTowardsEve entries and port-forward rules
//     that reference it. Provides access to dns-server and http-server-2.test
//     (10.21.21.70) only; no access to http-server-1.test, which exercises the gateway
//     firewall negative test.
//     RoutesTowardsEve on the app-network router cover the two air-gap subnets
//     (172.28.1.0/24 and 172.28.2.0/24) routed via app-gw (10.203.10.150), so that the
//     SDN router knows how to forward return traffic towards those private networks.
//
// The shared dns-server (10.16.16.25) resolves the controller hostname, http-server-1.test,
// and http-server-2.test, and is reachable from both ports.
var AppGatewayTopology = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
		{LogicalLabel: "eth1", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
		{LogicalLabel: "bridge1", Ports: []string{"eth1"}},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "mgmt-network",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.22.12.0/24",
				GwIp:   "172.22.12.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "172.22.12.10", ToIp: "172.22.12.150"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server", "http-server-1"},
			},
		},
		{
			// App-shared network for the gateway app's WAN port (Switch NI).
			// Static DHCP reservation maps app-gw's MAC to a fixed IP.
			// RoutesTowardsEve covers the two air-gap subnets behind app-gw.
			LogicalLabel: "app-network",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.203.10.0/24",
				GwIp:   "10.203.10.1",
				Dhcp: &api.DHCP{
					Enable:  true,
					IpRange: &api.IPRange{FromIp: "10.203.10.100", ToIp: "10.203.10.200"},
					StaticEntries: []*api.MACToIP{
						{Mac: "02:16:3e:01:00:00", Ip: "10.203.10.150"},
					},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			// No OutsideReachability; http-server-2 reachable but not http-server-1.
			// RoutesTowardsEve: route the two air-gap subnets via app-gw (10.203.10.150).
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"dns-server", "http-server-2"},
				RoutesTowardsEve: []*api.IPRoute{
					{DstNetwork: "172.28.1.0/24", Gateway: "10.203.10.150"},
					{DstNetwork: "172.28.2.0/24", Gateway: "10.203.10.150"},
				},
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-1",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-1",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server-2",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-2",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				// Reachable only from eth0 (mgmt); exercises the direct path.
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-1",
					Fqdn:         "http-server-1.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.20.20.0/24",
						Ip:     "10.20.20.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from HTTP server 1!\n",
					},
				},
			},
			{
				// Reachable only from eth1 (app-shared); exercises the gateway path.
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-2",
					Fqdn:         "http-server-2.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.21.21.0/24",
						Ip:     "10.21.21.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello from HTTP server 2!\n",
					},
				},
			},
		},
	},
}

// SeparateClusterPort is a multi-Ethernet network model with a dedicated cluster port per device.
var SeparateClusterPort = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel:  "dev1-eth0",
			AdminUp:       true,
			EveDeviceName: "edge-dev1",
		},
		{
			LogicalLabel:  "dev1-eth1",
			AdminUp:       true,
			EveDeviceName: "edge-dev1",
		},
		{
			LogicalLabel:  "dev2-eth0",
			AdminUp:       true,
			EveDeviceName: "edge-dev2",
		},
		{
			LogicalLabel:  "dev2-eth1",
			AdminUp:       true,
			EveDeviceName: "edge-dev2",
		},
		{
			LogicalLabel:  "dev3-eth0",
			AdminUp:       true,
			EveDeviceName: "edge-dev3",
		},
		{
			LogicalLabel:  "dev3-eth1",
			AdminUp:       true,
			EveDeviceName: "edge-dev3",
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"dev1-eth0", "dev2-eth0", "dev3-eth0"},
		},
		{
			LogicalLabel: "bridge1",
			Ports:        []string{"dev1-eth1", "dev2-eth1", "dev3-eth1"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "mgmt-and-app-network",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.20.0/24",
				GwIp:   "172.20.20.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
		},
		{
			LogicalLabel: "cluster-network",
			Bridge:       "bridge1",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "10.244.244.0/24",
				GwIp:   "10.244.244.1",
			},
			Router: &api.Router{
				OutsideReachability: false,
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server",
					Fqdn:         "dns-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv4().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		// This HTTP server can be used as a target for application connectivity testing.
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world!",
					},
				},
			},
		},
	},
}
