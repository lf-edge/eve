// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmodels

import (
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// LongFQDN is the FQDN of the longest registered domain name.
// Source: https://longest.domains/
const LongFQDN = "theofficialabsolutelongestdomainnameregisteredontheworldwideweb.international"

// SingleEthWithDHCP is a single-Ethernet network model with DHCP enabled.
var SingleEthWithDHCP = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
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
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "long-fqdn-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "long-fqdn-server",
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
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server2",
					Fqdn:         "http-server2.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.18.18.0/24",
						Ip:     "10.18.18.25",
					},
				},
				HttpPort: 8080,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from http-server2!",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "long-fqdn-server",
					Fqdn:         LongFQDN,
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.19.19.0/24",
						Ip:     "10.19.19.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from long-fqdn-server!",
					},
				},
			},
		},
	},
}

// SingleEthIPv6Only is a single-port model with NO IPv4 connectivity.
// EVE acquires a global-unicast IPv6 address via SLAAC and reaches the
// controller exclusively over IPv6. The SDN DNS server is IPv6-only so
// that EVE (with a v6-only port) can resolve the controller hostname.
// An IPv6-only HTTP server ("http-server.test") is included for application
// connectivity testing; its AAAA record is served by the SDN DNS server.
var SingleEthIPv6Only = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network0",
			Bridge:       "bridge0",
			// No Ipv4 field — IPv6-only segment.
			Ipv6: &api.NetworkIPConfig{
				Subnet: "fd3f:89fd:78c5::/64",
				GwIp:   "fd3f:89fd:78c5::1",
				// Only DNS is set, so SLAAC handles address assignment.
				Dhcp: &api.DHCP{
					Enable: true,
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
					// IPv6-only endpoint — reachable from the IPv6-only segment.
					Ipv6: &api.EndpointIPConfig{
						Subnet: "fd23:131b:6500::/64",
						Ip:     "fd23:131b:6500::1",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv6().String(),
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-server",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server",
								IpVersion:    api.IPVersion_IPV6,
							},
						},
					},
				},
				UpstreamServers: []string{
					"2001:4860:4860::8888", // Google DNS (IPv6)
					"2606:4700:4700::1111", // Cloudflare DNS (IPv6)
				},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server",
					Fqdn:         "http-server.test",
					// IPv6-only endpoint — no A record, only AAAA.
					Ipv6: &api.EndpointIPConfig{
						Subnet: "fdde:55a:74d4::/64",
						Ip:     "fdde:55a:74d4::7",
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

// SingleEthWithDHCPAndIPv6 is a single-Ethernet network model with dual-stack DHCP (IPv4 and IPv6).
var SingleEthWithDHCPAndIPv6 = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
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
			Ipv6: &api.NetworkIPConfig{
				Subnet: "fd3f:89fd:78c5::/64",
				GwIp:   "fd3f:89fd:78c5::1",
				Dhcp: &api.DHCP{
					Enable: true,
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
					Ipv6: &api.EndpointIPConfig{
						Subnet: "fd23:131b:6500::/64",
						Ip:     "fd23:131b:6500::1",
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
						FqdnSource: &api.DNSEntry_FqdnLiteral{
							FqdnLiteral: evetest.GetControllerHostname(),
						},
						IpSource: &api.DNSEntry_IpLiteral{
							IpLiteral: evetest.GetControllerIPv6().String(),
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
				UpstreamServers: []string{
					"8.8.8.8",              // Google DNS (IPv4)
					"2001:4860:4860::8888", // Google DNS (IPv6)
					"1.1.1.1",              // Cloudflare DNS (IPv4)
					"2606:4700:4700::1111", // Cloudflare DNS (IPv6)
				},
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
					Ipv6: &api.EndpointIPConfig{
						Subnet: "fdde:055a:74d4::/64",
						Ip:     "fdde:055a:74d4::7",
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

// SingleEthWithoutDHCP is a single-Ethernet network model without DHCP (static IP configuration).
var SingleEthWithoutDHCP = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "network0",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.20.0/24",
				GwIp:   "172.20.20.1",
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

var (
	// ProxyCACertPEM is the PEM-encoded CA certificate used to sign the proxy's TLS certificate.
	ProxyCACertPEM = "-----BEGIN CERTIFICATE-----\n" +
		"MIIDVTCCAj2gAwIBAgIUPGtlx1k08RmWd9RxiCKTXYnAUkIwDQYJKoZIhvcNAQEL\n" +
		"BQAwOjETMBEGA1UEAwwKemVkZWRhLmNvbTELMAkGA1UEBhMCVVMxFjAUBgNVBAcM\n" +
		"DVNhbiBGcmFuY2lzY28wHhcNMjIwOTA3MTcwMDE0WhcNMzIwNjA2MTcwMDE0WjA6\n" +
		"MRMwEQYDVQQDDAp6ZWRlZGEuY29tMQswCQYDVQQGEwJVUzEWMBQGA1UEBwwNU2Fu\n" +
		"IEZyYW5jaXNjbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQsi7IG\n" +
		"M8KApujL71MJXbuPQNn/g+RItQeehaFRcqcCcpFW4k1YveMNdf5HReKlAfufFtaa\n" +
		"IF368t33UlleblopLM8m8r9Ev1sSJOS1yYgU1HABjyw54LXBqT4tAf0xjlRaLn4L\n" +
		"QBUAS0TTywTppGXtNwXpxqdDuQdigNskqzEFaGI52IQezfGt7L2CeeJ/YJNcbImR\n" +
		"eCXMPwTatUHLLE29Qv8GQQfy7TpCXdXVLvQAyfZJi7lY7DjPqBab5ocnVTRcEpKz\n" +
		"FwH2+KTokQkU1UF614IveRF3ZOqqmrQvy1AdSvekFLIz2uP7xsfy3I3HNQcPJ4DI\n" +
		"5vNzBaE/hF5xK40CAwEAAaNTMFEwHQYDVR0OBBYEFPxOB5cxsf89x6KdFSTTFV2L\n" +
		"wta1MB8GA1UdIwQYMBaAFPxOB5cxsf89x6KdFSTTFV2Lwta1MA8GA1UdEwEB/wQF\n" +
		"MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFXqCJuq4ifMw3Hre7+X23q25jOb1nzd\n" +
		"8qs+1Tij8osUC5ekD21x/k9g+xHvacoJIOzsAmpAPSnwXKMnvVdAeX6Scg1Bvejj\n" +
		"TdXfNEJ7jcvDROUNjlWYjwiY+7ahDkj56nahwGjjUQdgCCzRiSYPOq6N1tRkn97a\n" +
		"i6+jB8DnTSDnv5j8xiPDbWJ+nv2O1NNsoHS91UrTqkVXxNItrCdPPh21hzrTJxs4\n" +
		"oSf4wbaF5n3E2cPpSAaXBEyxBdXAqUCIhP0q9/pgBTYuJ+eW467u4xWqUVi4iBtN\n" +
		"wVfYelYC2v03Rn433kv624oJDQ7MM5bDUv3nqPtkUys0ARwxs8tQCgg=\n" +
		"-----END CERTIFICATE-----"
	// ProxyCAKeyPEM is the PEM-encoded private key for the proxy CA certificate.
	ProxyCAKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0LIuyBjPCgKbo\n" +
		"y+9TCV27j0DZ/4PkSLUHnoWhUXKnAnKRVuJNWL3jDXX+R0XipQH7nxbWmiBd+vLd\n" +
		"91JZXm5aKSzPJvK/RL9bEiTktcmIFNRwAY8sOeC1wak+LQH9MY5UWi5+C0AVAEtE\n" +
		"08sE6aRl7TcF6canQ7kHYoDbJKsxBWhiOdiEHs3xrey9gnnif2CTXGyJkXglzD8E\n" +
		"2rVByyxNvUL/BkEH8u06Ql3V1S70AMn2SYu5WOw4z6gWm+aHJ1U0XBKSsxcB9vik\n" +
		"6JEJFNVBeteCL3kRd2Tqqpq0L8tQHUr3pBSyM9rj+8bH8tyNxzUHDyeAyObzcwWh\n" +
		"P4RecSuNAgMBAAECggEAazt75Pd2BNQHAtSlWplfdQq8gUJm4A452BAL3kgYYbe+\n" +
		"MiwwwfIICcNwL2eB+3NTq8syj4TpsKVzuJHDLDdcnEKXTa8TmKy06uHwnUJocJpd\n" +
		"GVCEQsErsWFSdhPZdDTzTdbihtfxSs6C/bLDyOe5lYRKVDWfqttOm0uP/11imehq\n" +
		"5CbnirPJF80i7SSR3ft743SbE9NMXy7IYlGZ9NDUaKcPVhH+oxEB81DodnIxk7BD\n" +
		"IiPa44m2XyCbDFWY9gmKGCr838tG8DG9at4SldG18JwobJsjFgOTJTIrPZEd8aUS\n" +
		"Wx21YITEzQG4RMp3/RvNNiWNgvqSPuuoov5qS0O8TQKBgQDkm5RRQGAr2f4Giodr\n" +
		"+CaSrOdTB2wGTS/w5xKktkOa/0ZVW4QOgKu04bSp8BJ88JvOfwdX8WuAqa+4ZQa1\n" +
		"d76Ya0nGotY125ZQ5RYgKaaFaWUJy/CAquet7cr7mbGWYhGbngL1qWQMkxcZlJnL\n" +
		"ZSR83c8oSUMNIsA2ZXnjh1+iBwKBgQDJw0mcpnrvOgf5MP7NSjiAMrt+YgRCcx2D\n" +
		"KPIZuxn6t0N9+HRnQC5EN3twSXp5HE2XjPn8jG1xl345E/Ev2t3vzbe8iabzcEne\n" +
		"w9/6Wqd5ENmk/Qib3T2RZshl1zymSRdSVZexcjd9f1nmsq1JyhEk5s4ZsIkk5U0Z\n" +
		"/3SM6NrQywKBgFaFm6j02HFAXChVndN7Y/33esWt9XCdHhvrGN9GLGgpXZFIxb5H\n" +
		"bLVVB2+Z8SVgW1fYNAtQ0AMuNddwRQ3BeF1vnciUMMbJiSaszab2nJO5xAflK+1G\n" +
		"wdDOQxjenpvwGgHv1+bqaXdo5EFGQL7+VMT9nj39HGeIU39DANLglY1ZAoGBALrU\n" +
		"4sJzix0hoKaJTzmsg/t6fxJ+EzGxRV/iN6XKEzmOIKpyut+tl+pFckG9WPLzWYp/\n" +
		"2jGZm/L29MRICixlQOTBm2W0FewRS+ZDfZFoBvLdvpzATwt96HhPNDzR/fCBeF4e\n" +
		"slR3zpigqBAv3rWYrx17uNgjGCwZRbdQTY36Rj3XAoGAOKrgsJkWPNV08Sw9DX6R\n" +
		"SyODv0NpdCKlGcDZX/LZc/imic0eCUww64ZqPFHHdRkIEj3cVtSTryqfXPFheVxB\n" +
		"JA/5Rtu/UAatNxhUwA3NT1WJewBsTQyds75Vwz0TBvqr0VWEi5GbxlZReLu7v5gj\n" +
		"rt3dAPD3c4Szs8PbWB9pGso=\n" +
		"-----END PRIVATE KEY-----"
)

// SingleEthWithDHCPAndExplicitProxy is a single-Ethernet network model with DHCP and an explicit HTTP proxy.
var SingleEthWithDHCPAndExplicitProxy = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
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
						PrivateDns: []string{"dns-server-for-device"},
					},
				},
			},
			Router: &api.Router{
				// Internet is reachable but firewall will block access to the controller
				// that bypasses proxy.
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server-for-device", "http-proxy"},
			},
		},
	},
	Firewall: &api.Firewall{
		Rules: []*api.FwRule{
			// It is not allowed to access the controller directly, proxy must be used.
			{
				SrcSubnet: "172.20.20.0/24",
				DstSubnet: evetest.GetControllerIPv4().String() + "/32",
				Action:    api.FwAction_FW_DROP,
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server-for-device",
					Fqdn:         "dns-server-for-device.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-proxy",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-proxy",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server-for-proxy",
					Fqdn:         "dns-server-for-proxy.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
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
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		ExplicitProxies: []*api.ExplicitProxy{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-proxy",
					Fqdn:         "http-proxy.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.18.18.0/24",
						Ip:     "10.18.18.25",
					},
				},
				Proxy: &api.Proxy{
					DnsClientConfig: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server-for-proxy"},
					},
					CaCertPem: ProxyCACertPEM,
					CaKeyPem:  ProxyCAKeyPEM,
					ProxyRules: []*api.ProxyRule{
						{
							ReqHost: "github.com",
							Action:  api.ProxyAction_PX_REJECT,
						},
						{
							Action: api.ProxyAction_PX_MITM,
						},
					},
				},
				HttpProxy: &api.ProxyPort{
					Port:        9090,
					ListenProto: api.ProxyListenProto_HTTP,
				},
				HttpsProxy: &api.ProxyPort{
					Port:        9091,
					ListenProto: api.ProxyListenProto_HTTP,
				},
			},
		},
	},
}

// SingleEthWithDHCPAndTransparentProxy is a single-Ethernet network model with DHCP and a transparent proxy.
var SingleEthWithDHCPAndTransparentProxy = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
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
			TransparentProxy: "tproxy",
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
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		TransparentProxies: []*api.TransparentProxy{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "tproxy",
					Fqdn:         "tproxy.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
					},
				},
				Proxy: &api.Proxy{
					DnsClientConfig: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
					CaCertPem: ProxyCACertPEM,
					CaKeyPem:  ProxyCAKeyPEM,
					ProxyRules: []*api.ProxyRule{
						{
							Action: api.ProxyAction_PX_MITM,
						},
					},
				},
			},
		},
	},
}

// SingleEthWithDHCPAndAutoDiscoveredProxy is a single-Ethernet network model with DHCP and a WPAD auto-discovered proxy.
var SingleEthWithDHCPAndAutoDiscoveredProxy = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
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
						PrivateDns: []string{"dns-server-for-device"},
					},
				},
			},
			Router: &api.Router{
				// Internet is reachable but firewall will block access to the controller
				// that bypasses proxy.
				OutsideReachability: true,
				ReachableEndpoints:  []string{"dns-server-for-device", "http-proxy", "wpad"},
			},
		},
	},
	Firewall: &api.Firewall{
		Rules: []*api.FwRule{
			// It is not allowed to access the controller directly, proxy must be used.
			{
				SrcSubnet: "172.20.20.0/24",
				DstSubnet: evetest.GetControllerIPv4().String() + "/32",
				Action:    api.FwAction_FW_DROP,
			},
		},
	},
	Endpoints: &api.Endpoints{
		DnsServers: []*api.DNSServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server-for-device",
					Fqdn:         "dns-server-for-device.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.16.0/24",
						Ip:     "10.16.16.25",
					},
				},
				StaticEntries: []*api.DNSEntry{
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "http-proxy",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-proxy",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
					{
						FqdnSource: &api.DNSEntry_EndpointFqdnRef{
							EndpointFqdnRef: "wpad",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "wpad",
								IpVersion:    api.IPVersion_IPV4,
							},
						},
					},
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "dns-server-for-proxy",
					Fqdn:         "dns-server-for-proxy.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.17.17.0/24",
						Ip:     "10.17.17.25",
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
				},
				UpstreamServers: []string{"8.8.8.8", "1.1.1.1"},
			},
		},
		ExplicitProxies: []*api.ExplicitProxy{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-proxy",
					Fqdn:         "http-proxy.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.18.18.0/24",
						Ip:     "10.18.18.25",
					},
				},
				Proxy: &api.Proxy{
					DnsClientConfig: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server-for-proxy"},
					},
					CaCertPem: ProxyCACertPEM,
					CaKeyPem:  ProxyCAKeyPEM,
					ProxyRules: []*api.ProxyRule{
						{
							ReqHost: "github.com",
							Action:  api.ProxyAction_PX_REJECT,
						},
						{
							Action: api.ProxyAction_PX_MITM,
						},
					},
				},
				HttpProxy: &api.ProxyPort{
					Port:        9090,
					ListenProto: api.ProxyListenProto_HTTP,
				},
				HttpsProxy: &api.ProxyPort{
					Port:        9091,
					ListenProto: api.ProxyListenProto_HTTP,
				},
			},
		},
		HttpServers: []*api.HTTPServer{
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "wpad",
					Fqdn:         "wpad.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.19.19.0/24",
						Ip:     "10.19.19.25",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/wpad.dat": {
						ContentType: "application/x-ns-proxy-autoconfig",
						Content: "function FindProxyForURL (url, host) {\n" +
							"  if (host == 'github.com') {\n" +
							"    return 'DIRECT';\n" +
							"  }\n" +
							"  if (url.substring(0, 5) == 'http:') {\n" +
							"    return 'PROXY http-proxy.test:9090';\n" +
							"  }\n" +
							"  if (url.substring(0, 6) == 'https:') {\n" +
							"    return 'PROXY http-proxy.test:9091';\n" +
							"  }\n" +
							"  return 'DIRECT';\n" +
							"}",
					},
				},
			},
		},
	},
}

var (
	// PnacRootCACertPEM is the PEM-encoded root CA certificate used for 802.1X/PNAC authentication.
	PnacRootCACertPEM = "-----BEGIN CERTIFICATE-----\n" +
		"MIIDbzCCAlegAwIBAgIUIBGoXOsp3/1npf65ev43t5OuQugwDQYJKoZIhvcNAQEL\n" +
		"BQAwPzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0V4YW1wbGUxDDAKBgNVBAsMA0xh\n" +
		"YjEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yNjA0MDIxNjE2MTJaFw0zNjAzMzAxNjE2\n" +
		"MTJaMD8xCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdFeGFtcGxlMQwwCgYDVQQLDANM\n" +
		"YWIxEDAOBgNVBAMMB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
		"AoIBAQDxhcPxwJklXQe5tDaSoUGXbxBKHTbL5bh6Fb59zwQ01pYMiR4Q52g0lg4t\n" +
		"QOdlWG+mdfXKrc3DHECGVkKTFIRZtujYsskK52W3LSDpw9nDqiRm+r0qIEfJr6Kv\n" +
		"xBY0zknN7XARgJG6KZ13Q1SDsrfB2B+6Qs6J5j2U9/ldOWooV+8hSnVYkBmdJxDq\n" +
		"d6e9GPi57V2ct0ZsmaOu/979RReunOpopty8XwNjjvreAUjZ3BNPj/kT7LiekC5r\n" +
		"i+clqQe96ksLaAE0P+2EWQi3JO8owG+JCQ7VdY0PbqtULMifFsRUc5z776dPy/Zl\n" +
		"aY28VYecFpzNyvE3ofTkOOOmdgIZAgMBAAGjYzBhMB8GA1UdIwQYMBaAFJ3Y+HgR\n" +
		"mAiZB1x3MBEDavLOjdenMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEG\n" +
		"MB0GA1UdDgQWBBSd2Ph4EZgImQdcdzARA2ryzo3XpzANBgkqhkiG9w0BAQsFAAOC\n" +
		"AQEAUkiAoV0bejMRzv4fqxTHDiq1rrF/i2Oc89OWjnSqiUxFrq8HjW/+c4gvezZQ\n" +
		"fSC/At8Ml6O2/51/7LfMWvfjNn9hkG6ZsjdzbVlsj81Z7migUo9w7hqoATM9x81C\n" +
		"b+a88JwiMxCMnQSTmUKbSE5EU+hMLiuxXn37A7LSZRdjV1iQo18FOHCjHeU1Pxzr\n" +
		"sl0ZenvuNTDo5DtZw6THl8idLe91VJuVgz+PHpJ4bwxlqIdFD3FCrYREG5RFICfg\n" +
		"Wco2oFoauGf7liZG7N6g3RDM8rKjVdgB/bi8tFIBG2UqbxBXXzu7oUK684HpFr7W\n" +
		"mpG+FJCVr4u7GeGGS8ktKIHFPA==\n" +
		"-----END CERTIFICATE-----"

	// PnacRootCAKeyPEM is the PEM-encoded private key for the PNAC root CA certificate.
	PnacRootCAKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEogIBAAKCAQEA8YXD8cCZJV0HubQ2kqFBl28QSh02y+W4ehW+fc8ENNaWDIke\n" +
		"EOdoNJYOLUDnZVhvpnX1yq3NwxxAhlZCkxSEWbbo2LLJCudlty0g6cPZw6okZvq9\n" +
		"KiBHya+ir8QWNM5Jze1wEYCRuimdd0NUg7K3wdgfukLOieY9lPf5XTlqKFfvIUp1\n" +
		"WJAZnScQ6nenvRj4ue1dnLdGbJmjrv/e/UUXrpzqaKbcvF8DY4763gFI2dwTT4/5\n" +
		"E+y4npAua4vnJakHvepLC2gBND/thFkItyTvKMBviQkO1XWND26rVCzInxbEVHOc\n" +
		"+++nT8v2ZWmNvFWHnBaczcrxN6H05DjjpnYCGQIDAQABAoIBAAoJ0SgtPp0QcRlC\n" +
		"Io1VBkWVuEIau71p+cRm2FxUEqzIvHZrhPEXHrwmZN/Zoj4SmM7834kbtzRXg/dx\n" +
		"aPv1YgwOiT5nrYNDNQ8rerVsmywoPrIVbgmGfou+vcH7bu0/I7WOge/Tfa5H1R0k\n" +
		"LCrH7oSwITiovS5H5qHx7cHdRVde15hXWcIaaM5+IQ/n6HBRzBnt3mGnDAHACbQo\n" +
		"El7HIxsKcE5WZ/M+DSeS/nlexEjPUrvgtBNoxpPtVgkcHmkyQQwaFK8z6Q4IYboP\n" +
		"6LvjB6Ii6G+xU5mnc4fzGdWUYgiiQ3yYdDeC3NENyAyie0FZWMBroN8CBfGbKFKP\n" +
		"PaBEEb8CgYEA8905SCculxEV5F7TQW7QnkwYQGE90NWldlyLNmqPFVumTsxA76lx\n" +
		"MpOWMSdBNQYPIwbWptVUeTbvs5QoYFJD1PUb6r6E4hyt4ZeYANYmwiZpKLT5dbAB\n" +
		"Ct3Vr4xh9cYdN6EygmQcLqND5CL3HsLPlRcYohQJ07l97gUNiYXIg/cCgYEA/Yq1\n" +
		"sZJ34IBrU57KEFPhcKTj9mWHdQt6n7f1o1o1MDL+3VN09ujOQaomBtpk6K6XjV3z\n" +
		"fdxb5KBfWAQx2GkwQ1uTnCZy3OVXtK+O8pn+ATdfIHbomJMoEHSfiR+GEIIWfpGr\n" +
		"n3gn3/NA+3xpqnQfrNMrQHK2lZJpp/Ty2dS7Bm8CgYBsT7GFboGu7xO+Hq/NvB5E\n" +
		"cJ/E2GvQOVQIQgpC3Qk3/0DadrXQvH1ebVaj9j9sAYjvkbX823ttaw0DwaY9QcyG\n" +
		"5WbE2GHE2+AO9nm4xWTpjo3eWqMBtm6AGQ8zrTJFKv0HHD2G1FgADtu0lCMWMoho\n" +
		"O53hPu0ucJCSCwR8NENe+QKBgFOpBoUeeHHazg9ckP5MP1JFBneSTt0fOYokUGhj\n" +
		"ZrON0C1F0Y17ijt+omeWfr+MhLN/8c1w/d110aAgWjY3l1ZSjGV1Bme/QW58k2WX\n" +
		"zImoNLpooh1eSVUMtmuvvDQMSNHgzUmkgzvRb3rMNa2p/Z2wXFA6yeaW1kg2ej/I\n" +
		"gyH/AoGAOn1NGzg38h1DjYQRPl4Hwle3Vc3z4D8WmNSuUqgDTGbfMCof/Vxnpk+5\n" +
		"TTkL05pxrUzs4OjhWnkQxnCpSKLfW0T9kqNsQrW7OEJq1saB93OPx7wwrMmwnIEc\n" +
		"j+B9gN25cnM18lZ9+ZWjINsZXZ8OX1g9fSAuRCKXumXHdmB0TZk=\n" +
		"-----END RSA PRIVATE KEY-----"

	// PnacScepCACertPEM is the PEM-encoded SCEP CA certificate used for PNAC certificate enrollment.
	PnacScepCACertPEM = "-----BEGIN CERTIFICATE-----\n" +
		"MIIDcjCCAlqgAwIBAgIUDxaHbzjqFf8DSelj+SuCe/YflhQwDQYJKoZIhvcNAQEL\n" +
		"BQAwPzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0V4YW1wbGUxDDAKBgNVBAsMA0xh\n" +
		"YjEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yNjA0MDIxNjE2MzRaFw0zMTA0MDExNjE2\n" +
		"MzRaMD8xCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdFeGFtcGxlMQwwCgYDVQQLDANM\n" +
		"YWIxEDAOBgNVBAMMB1NDRVAgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
		"AoIBAQDUHEaxNBRX/YjUSxXUBTif0UtCuGz3o+L0zuxF0e6g9/WhdBrHlgVGfw/4\n" +
		"mUUcI3pgetKt0AjRrvU+JekTR/pydx+DoXUJZExEb1EJXcPd7mfaIfJrUdHErzhU\n" +
		"2r2Qq+NYOCNrXDaCYnnWLTeigjnh0gjjyl27J0sAq4Q4aOIRT9JatSml2HTWsK9b\n" +
		"A9VeyQvDyX07rbMkkCyiAdxxMBnAralRMJsGLcwrpK21uoLGAQVGSG0NfS4gUspK\n" +
		"ePa9G3VYW08a0iab6dtUoQ/L/S0Cu+dwaOrrczHwgM4iyd7sPJ5iZ2RQffuLp9U1\n" +
		"KFzBHRYno38bQZaGl/SXhRFWioN5AgMBAAGjZjBkMBIGA1UdEwEB/wQIMAYBAf8C\n" +
		"AQAwDgYDVR0PAQH/BAQDAgGmMB0GA1UdDgQWBBRs7ehQ+cMZ9U1kvNX+GC+gJRDJ\n" +
		"nDAfBgNVHSMEGDAWgBSd2Ph4EZgImQdcdzARA2ryzo3XpzANBgkqhkiG9w0BAQsF\n" +
		"AAOCAQEAAxyy0pBZ1TrDXqsg5DSe52nIn8I9qxJcGUHnD95hj8yIYKk/PM8KeLEL\n" +
		"mI2NxyBW68Q1x1ayudR2d+RYm/nDp26otbdBkA9RLDdA/O2mFdQr1kyaKJeZUq7S\n" +
		"K0aYAXUXRY0l9FfCTwuhP6sacEzOd15lxJleOmEVc28DnmSXVnCli/8dMZ2iMhTX\n" +
		"wWUfEhyxqTvnXswvzPNIFdgsCv0jyAfsycF44wy/bkvRwr/PTE7PXaq6DpMDvYI6\n" +
		"v/TKO+9fQgNKaLEmkSpeun2nhVwH2Vt4wguzvwA0vrLH8GLkfXFneV6+2njIhmJl\n" +
		"ohrPj+TXcFCbSMntv/oW2QPhfcorcA==\n" +
		"-----END CERTIFICATE-----"

	// PnacScepCAKeyPEM is the PEM-encoded private key for the PNAC SCEP CA certificate.
	PnacScepCAKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEA1BxGsTQUV/2I1EsV1AU4n9FLQrhs96Pi9M7sRdHuoPf1oXQa\n" +
		"x5YFRn8P+JlFHCN6YHrSrdAI0a71PiXpE0f6cncfg6F1CWRMRG9RCV3D3e5n2iHy\n" +
		"a1HRxK84VNq9kKvjWDgja1w2gmJ51i03ooI54dII48pduydLAKuEOGjiEU/SWrUp\n" +
		"pdh01rCvWwPVXskLw8l9O62zJJAsogHccTAZwK2pUTCbBi3MK6SttbqCxgEFRkht\n" +
		"DX0uIFLKSnj2vRt1WFtPGtImm+nbVKEPy/0tArvncGjq63Mx8IDOIsne7DyeYmdk\n" +
		"UH37i6fVNShcwR0WJ6N/G0GWhpf0l4URVoqDeQIDAQABAoIBAGWODEK3nq3qU+Lg\n" +
		"+FiFD3FlcdVGG9YNf5KaqAFd3BTx44cj4daBe5EfMPRj3fT0/5jF9a0Gl9JdJEpX\n" +
		"OFrk8YJwioQpf7G5ddKmQXRskmTlyo9kBX9gs0CqbBwkhvKHedg5OKwkgGy43YCw\n" +
		"MZz7IN+AAoWd1HbQ/1YYyLuBbAvA/tE4Lt+idQf6JoD/0lsrNshdEt4XP8xf4URb\n" +
		"XFO2Q9ZXkfr8bAqDbIfUYpDktfXBq4j4yIdZ+btYH5tcq4p3qh9UDxn5GRZvoSoi\n" +
		"L4YOG5QqgrFpVu3WfQmxm29x3OhpcvD8gqS9vX0TIiR75hySdY01lRVx4P31sQ+n\n" +
		"gMnv7SkCgYEA7nov5tLCK5AFLC7gWyZ5WsHkGCbY3LT2kpnbWCAgfUmXfJ5Oospo\n" +
		"vPtDTgy2RB+H29fWm+dpcucAphRjuxEcoTmSYtzIXq74/EoonTHuWQR6yGLcrINl\n" +
		"9LBm2SJO/mfV0Nc8adQnMIUX9Hbep3Onkfr06dQ3P1+1kbwurBEHIucCgYEA47If\n" +
		"aJV+xqMlYaGaayKD25lBWS05f8dOsUgoVrvq0dVrxZYH2YiDhWWIwpSsy0i79Cq9\n" +
		"+ShGmXPzGj7kVumIsACUjrp4pb6xNHaTt2jIeLJH6yYOUkmXomH4dwqFUS9ahXeX\n" +
		"fZmoaN8Jah7inIur9zaX8uWiqFjwlw+MPRZAup8CgYBSZ5ph0nYSA4QmDlSsapEI\n" +
		"kXM1/UZ2jXmekte+jetsH5/fCfz2N6cVlmVddPsOcy7JAr4/xSkk8TnCKc2EeJdC\n" +
		"BtjUnKIIRcH3u9Bo8TYBQJEE6VSDsCvs73+6jCZrtomlzporn4mjNHpgmSq7BjXj\n" +
		"NaqnmhM1LOda4oHmJ0QmBQKBgQCYQvfP5xBk4ppPxFJPzD/irIRPjveBZBVSZc9b\n" +
		"2MP5V79+3IoZRLm2jaQ7glJeih/t8lshb3ZujWQGrAHjwL0//NNa8oVVSMSVMaos\n" +
		"HuzYEVgYflVbX4z/8IXHjQiDtqfQ0p1CR2uf3W4dQdQGHTx8z0wjCL6R1w/j5GjC\n" +
		"PMxCPwKBgQCE/CTdLHyY0CO7oLnDJ9XEXr1ongAPGrWXvxBUXDOvQYOS4CsKP0cW\n" +
		"qXfMlQlHDOG5Nzjv1/fgw7OWzw1XzLCtp06f5Ek938p08/oCmVtJtFVBUmjs6TRD\n" +
		"bckl0B7XRM+RnNjbeqSBBIJYej5sqJFOtvYn83Wt8uVAq+s2Ln2e7A==\n" +
		"-----END RSA PRIVATE KEY-----"
)

// SingleEthWithPNAC returns a single-Ethernet network model with 802.1X/PNAC authentication,
// optionally requiring a SCEP proxy for certificate enrollment.
func SingleEthWithPNAC(requireSCEPProxy bool) *api.NetworkModel {
	model := &api.NetworkModel{
		Ports: []*api.Port{
			{
				LogicalLabel: "eth0",
				AdminUp:      true,
			},
		},
		Bridges: []*api.Bridge{
			{
				LogicalLabel: "bridge0",
				Ports:        []string{"eth0"},
				Pnac: &api.PNAC{
					Enable_8021X: true,
					CaCertPem:    PnacRootCACertPEM,
					CaKeyPem:     PnacRootCAKeyPEM,
					Users: []*api.EAPUser{
						{
							Identity: "evetest",
							Methods:  []api.EAPMethod{api.EAPMethod_EAP_METHOD_TLS},
						},
					},
					PreAuthVlanId:  10,
					PostAuthVlanId: 20,
				},
			},
		},
		Networks: []*api.Network{
			{
				LogicalLabel: "onboarding-network",
				Bridge:       "bridge0",
				VlanId:       10,
				Ipv4: &api.NetworkIPConfig{
					Subnet: "172.20.10.0/24",
					GwIp:   "172.20.10.1",
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
				LogicalLabel: "authenticated-network",
				Bridge:       "bridge0",
				VlanId:       20,
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
								EndpointFqdnRef: "scep-server",
							},
							IpSource: &api.DNSEntry_EndpointIpRef{
								EndpointIpRef: &api.EndpointIPRef{
									LogicalLabel: "scep-server",
									IpVersion:    api.IPVersion_IPV4,
								},
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
			ScepServers: []*api.SCEPServer{
				{
					Endpoint: &api.Endpoint{
						LogicalLabel: "scep-server",
						Fqdn:         "scep-server.test",
						Ipv4: &api.EndpointIPConfig{
							Subnet: "10.17.17.0/24",
							Ip:     "10.17.17.25",
						},
					},
					Port:              8080,
					CaCertPem:         PnacScepCACertPEM,
					CaKeyPem:          PnacScepCAKeyPEM,
					ChallengePassword: "123456789",
				},
			},
			// This HTTP server is accessible only after successful port authentication.
			HttpServers: []*api.HTTPServer{
				{
					Endpoint: &api.Endpoint{
						LogicalLabel: "http-server",
						Fqdn:         "http-server.test",
						Ipv4: &api.EndpointIPConfig{
							Subnet: "10.18.18.0/24",
							Ip:     "10.18.18.25",
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

	// Configure Firewall.
	// Common allow rules.
	rules := []*api.FwRule{
		// Allow edge-device to resolve Controller and SCEP server IP addresses:
		{
			SrcSubnet: "172.20.10.0/24",
			DstSubnet: "10.16.16.25/32", // DNS Server
			Action:    api.FwAction_FW_ALLOW,
		},
		// Allow edge-device to onboard and retrieve configuration:
		{
			SrcSubnet: "172.20.10.0/24",
			DstSubnet: evetest.GetControllerIPv4().String() + "/32",
			Action:    api.FwAction_FW_ALLOW,
		},
		// Allow SSH access to EVE even when port is not authenticated:
		{
			SrcSubnet: "172.20.10.0/24",
			DstSubnet: evetest.GetSrcIPv4ForEVEAccess().String() + "/32",
			Action:    api.FwAction_FW_ALLOW,
		},
	}

	// Optionally allow direct access to the SCEP server.
	if !requireSCEPProxy {
		rules = append(rules, &api.FwRule{
			SrcSubnet: "172.20.10.0/24",
			DstSubnet: "10.17.17.25/32", // SCEP server
			Action:    api.FwAction_FW_ALLOW,
		})
	}

	// Default drop.
	rules = append(rules, &api.FwRule{
		SrcSubnet: "172.20.10.0/24",
		Action:    api.FwAction_FW_DROP,
	})

	model.Firewall = &api.Firewall{
		// Allow onboarding-network to access only explicitly permitted services;
		// drop all other traffic.
		Rules: rules,
	}
	return model
}

// SingleEthWithVLANSubInterfaces is a single-port model where three traffic
// streams share eth0: VLAN 10 (tagged, management + controller-reachable),
// VLAN 20 (tagged, application traffic only), and untagged (application traffic
// only). Each stream has its own DHCP-served subnet and a dedicated HTTP server
// endpoint that is reachable only from that stream's segment. The DNS server is
// reachable from all three segments so hostnames can be resolved everywhere.
var SingleEthWithVLANSubInterfaces = &api.NetworkModel{
	Ports: []*api.Port{
		{LogicalLabel: "eth0", AdminUp: true},
	},
	Bridges: []*api.Bridge{
		{LogicalLabel: "bridge0", Ports: []string{"eth0"}},
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
				ReachableEndpoints:  []string{"dns-server", "http-server-10"},
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
			LogicalLabel: "network-untagged",
			Bridge:       "bridge0",
			Ipv4: &api.NetworkIPConfig{
				Subnet: "192.168.77.0/24",
				GwIp:   "192.168.77.1",
				Dhcp: &api.DHCP{
					Enable:     true,
					IpRange:    &api.IPRange{FromIp: "192.168.77.10", ToIp: "192.168.77.20"},
					DomainName: "test",
					Dns: &api.DNSClientConfig{
						PrivateDns: []string{"dns-server"},
					},
				},
			},
			Router: &api.Router{
				OutsideReachability: false,
				ReachableEndpoints:  []string{"dns-server", "http-server-untagged"},
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
							EndpointFqdnRef: "http-server-10",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-10",
								IpVersion:    api.IPVersion_IPV4,
							},
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
							EndpointFqdnRef: "http-server-untagged",
						},
						IpSource: &api.DNSEntry_EndpointIpRef{
							EndpointIpRef: &api.EndpointIPRef{
								LogicalLabel: "http-server-untagged",
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
					LogicalLabel: "http-server-10",
					Fqdn:         "http-server-10.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.10.0/24",
						Ip:     "10.16.10.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from HTTP server for VLAN 10\n",
					},
				},
			},
			{
				Endpoint: &api.Endpoint{
					LogicalLabel: "http-server-20",
					Fqdn:         "http-server-20.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.20.0/24",
						Ip:     "10.16.20.70",
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
					LogicalLabel: "http-server-untagged",
					Fqdn:         "http-server-untagged.test",
					Ipv4: &api.EndpointIPConfig{
						Subnet: "10.16.77.0/24",
						Ip:     "10.16.77.70",
					},
				},
				HttpPort: 80,
				Paths: map[string]*api.HTTPContent{
					"/helloworld": {
						ContentType: "text/plain",
						Content:     "Hello world from HTTP server for untagged network\n",
					},
				},
			},
		},
	},
}

// SingleEthWithMgmtAndAppVLANs is a single-port network model where management
// and application traffic are separated using 802.1Q VLANs.
var SingleEthWithMgmtAndAppVLANs = &api.NetworkModel{
	Ports: []*api.Port{
		{
			LogicalLabel: "eth0",
			AdminUp:      true,
		},
	},
	Bridges: []*api.Bridge{
		{
			LogicalLabel: "bridge0",
			Ports:        []string{"eth0"},
		},
	},
	Networks: []*api.Network{
		{
			LogicalLabel: "mgmt-vlan",
			Bridge:       "bridge0",
			VlanId:       100,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.100.0/24",
				GwIp:   "172.20.100.1",
				Dhcp: &api.DHCP{
					Enable:     true,
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
			LogicalLabel: "app-vlan",
			Bridge:       "bridge0",
			VlanId:       200,
			Ipv4: &api.NetworkIPConfig{
				Subnet: "172.20.200.0/24",
				GwIp:   "172.20.200.1",
				Dhcp: &api.DHCP{
					Enable:     true,
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
