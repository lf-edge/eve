// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

const (
	// PhysIfTypename : typename for physical network interfaces.
	PhysIfTypename = "Physical-Interface"
	// IfHandleTypename : typename for network interface handle.
	IfHandleTypename = "Interface-Handle"
	// NetNamespaceTypename : typename for network namespaces.
	NetNamespaceTypename = "Network-Namespace"
	// BondTypename : typename for bond interface.
	BondTypename = "Bond"
	// BridgeTypename : typename for bridges.
	BridgeTypename = "Bridge"
	// VethTypename : typename for veths.
	VethTypename = "Veth"
	// SysctlTypename : typename for item representing kernel
	// parameters set using sysctl for a given net namespace.
	SysctlTypename = "Sysctl"
	// DhcpClientTypename : typename for DHCP/DHCPv6 client.
	DhcpClientTypename = "DHCP-Client"
	// DhcpServerTypename : typename for DHCP/DHCPv6 server.
	DhcpServerTypename = "DHCP-Server"
	// DNSServerTypename : typename for DNS server.
	DNSServerTypename = "DNS-Server"
	// RouteTypename : typename for IP route.
	RouteTypename = "Route"
	// IPRuleTypename : typename for IP rule.
	IPRuleTypename = "IP-Rule"
	// IPtablesChainTypename : typename for a single iptables chain (IPv4).
	IPtablesChainTypename = "Iptables-Chain"
	// IP6tablesChainTypename : typename for a single ip6tables chain (IPv6).
	IP6tablesChainTypename = "Ip6tables-Chain"
	// HTTPProxyTypename : typename for HTTP proxy.
	HTTPProxyTypename = "HTTP-Proxy"
	// HTTPServerTypename : typename for HTTP server.
	HTTPServerTypename = "HTTP-Server"
	// TrafficControlTypename : typename for TC rules applied to physical interface.
	TrafficControlTypename = "Traffic-Control"
	// RadvdTypename : typename for radvd - router advertisement daemon for IPv6.
	RadvdTypename = "Radvd"
	// TunTypename : typename for TUN interfaces.
	TunTypename = "TUN"
	// SCEPServerTypename : typename for SCEP server.
	SCEPServerTypename = "SCEP-Server"
	// HostapdTypename : typename for Hostapd.
	HostapdTypename = "Hostapd"
)
