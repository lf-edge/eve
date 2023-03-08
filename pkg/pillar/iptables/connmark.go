// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package iptables

// Connection mark is used to remember for a given flow to which application it belongs
// and which ACE was applied.
// The 32 bits of a connmark are used as follows:
//
//	+------------------------+---------------+------------------+
//	| Application ID (8bits) | Action (1bit) | ACE ID (23 bits) |
//	+------------------------+---------------+------------------+
//
// where: Drop action = 1; Allow action = 0
const (
	// AppIDMask : bits of the connection mark allocated to store application ID.
	AppIDMask = 0xff << 24
	// AceActionMask : bit of the connection mark used to store the action.
	AceActionMask = 0x1 << 23
	// AceDropAction : bit representation of the Drop action.
	AceDropAction = AceActionMask
	// AceIDMask : bits of the connection mark allocated to store ACE ID.
	AceIDMask = 0x7fffff
	// DefaultDropAceID : by default, traffic not matched by any ACE is dropped.
	// For this default rule we use the maximum integer value available for ACE ID.
	DefaultDropAceID = AceIDMask
)

// ControlProtocolMarkingIDMap : Map describing the control flow marking values
// (for implicit, i.e. not user defined, ACL rules) that we intend to use.
// XXX It is only read from, never written to, hence no concurrency.
// But LockedStringMap would be better.
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

// GetConnmark : create connection mark corresponding to the given attributes.
func GetConnmark(appID uint8, aceID uint32, drop bool) uint32 {
	mark := uint32(appID)<<24 | aceID
	if drop {
		mark |= AceDropAction
	}
	return mark
}

// ParseConnmark : parse attributes stored inside a connection mark.
func ParseConnmark(mark uint32) (appID uint8, aceID uint32, drop bool) {
	appID = uint8(mark >> 24)
	aceID = mark & AceIDMask
	drop = (mark & AceActionMask) == AceDropAction
	return
}
