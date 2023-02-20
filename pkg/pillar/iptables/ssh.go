// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package iptables

// ControlProtocolMarkingIDMap : Map describing the control flow
// marking values that we intend to use.
// XXX Only used by nim currently hence no concurrency.
//
//	But LockedStringMap would be better.
var ControlProtocolMarkingIDMap = map[string]string{
	// INPUT flows for HTTP, SSH & GUACAMOLE
	"in_http_ssh_guacamole": "1",
	// INPUT flows for VNC
	"in_vnc": "2",
	// There was some feature here that used marking values "3" & "4".
	// Marking values "3" & "4" are unused as of now.

	// OUTPUT flows for all types
	"out_all": "5",
	// App initiated UDP flows towards dom0 for DHCP
	"app_dhcp": "6",
	// App initiated TCP/UDP flows towards dom0 for DNS
	"app_dns": "7",
	// 8 : deprecated (previously: VPN control packets)
	// ICMP and ICMPv6
	"in_icmp": "9",
	// DHCP packets originating from outside
	// (e.g. DHCP multicast requests from other devices on the same network)
	"in_dhcp": "10",
}
