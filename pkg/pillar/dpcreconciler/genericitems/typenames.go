// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

const (
	// IOHandleTypename : typename for network interface handle.
	IOHandleTypename = "IO-Handle"
	// AdapterTypename : typename for network adapters
	// Not implemented in genericitems (implementation specific to network stack).
	AdapterTypename = "Adapter"
	// AdapterAddrsTypename : typename for allocated network adapter IP addresses.
	AdapterAddrsTypename = "Adapter-Addresses"
	// ArpTypename : typename for static ARP entries.
	// Not implemented in genericitems (implementation specific to network stack).
	ArpTypename = "ARP-Entry"
	// BondTypename : typename for bond interface.
	// Not implemented in genericitems (implementation specific to network stack).
	BondTypename = "Bond"
	// DhcpcdTypename : typename for dhcpcd program (a DHCP and DHCPv6 client).
	DhcpcdTypename = "DHCP-Client"
	// PhysIfTypename : typename for physical network interfaces.
	PhysIfTypename = "Physical-Interface"
	// ResolvConfTypename : typename for singleton item representing resolv.conf.
	ResolvConfTypename = "Resolv-Conf"
	// RouteTypename : typename for network route.
	// Not implemented in genericitems (implementation specific to network stack).
	RouteTypename = "Route"
	// SSHAuthKeysTypename : typename for singleton item representing file authorized_keys.
	SSHAuthKeysTypename = "SSH-Authorized-Keys"
	// VlanTypename : typename for VLAN sub-interface.
	// Not implemented in genericitems (implementation specific to network stack).
	VlanTypename = "VLAN"
	// WlanTypename : typename for WLAN configuration.
	// Not implemented in genericitems (implementation specific to network stack).
	WlanTypename = "WLAN"
	// WwanTypename : typename for WWAN (LTE) configuration (read by wwan microservice).
	WwanTypename = "WWAN"
)
