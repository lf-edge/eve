// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package iptables

// Connection mark is used to remember for a given flow to which application it belongs
// and which ACE was applied.
// The 32 bits of a connmark are used as follows:
//
//	+------------------------+---------------+-----------------+------------------+
//	| Application ID (8bits) | Action (1bit) | User ACE (1bit) | ACE ID (22 bits) |
//	+------------------------+---------------+-----------------+------------------+
//
// Where:
//
//	Action: 1 means to drop the flow, 0 to allow it
//	User ACE: 1 is used for user-configured ACE, 0 for automatically added rules
const (
	// AppIDMask : bits of the connection mark allocated to store application ID.
	AppIDMask = 0xff << 24
	// AceActionMask : bit of the connection mark used to store the action.
	AceActionMask = 0x1 << 23
	// AceDropAction : bit representation of the Drop action.
	AceDropAction = AceActionMask
	// AceFromUser : bit value set for user-defined ACEs.
	AceFromUser = 0x1 << 22
	// AceIDMask : bits of the connection mark allocated to store ACE ID.
	AceIDMask = 0x3fffff
	// DefaultDropAceID : by default, traffic not matched by any ACE is dropped.
	// For this default rule we use the maximum integer value available for ACE ID.
	DefaultDropAceID = AceIDMask
)

// ControlProtocolMarkingIDMap : Map describing the control flow marking values
// (for implicit, i.e. not user defined, ACL rules) that we intend to use.
// XXX It is only read from, never written to, hence no concurrency.
// But LockedStringMap would be better.
var ControlProtocolMarkingIDMap = map[string]uint32{
	// INPUT flows for HTTP, SSH & GUACAMOLE
	"in_http_ssh_guacamole": 1,
	// INPUT flows for VNC
	"in_vnc": 2,
	// There was some feature here that used marking values "3" & "4".
	// Marking values "3" & "4" are unused as of now.

	// OUTPUT flows for all types
	"out_all": 5,
	// App initiated UDP flows towards dom0 for DHCP
	"app_dhcp": 6,
	// App initiated TCP/UDP flows towards dom0 for DNS
	"app_dns": 7,
	// 8 : deprecated (previously: VPN control packets)
	// ICMP and ICMPv6
	"in_icmp": 9,
	// DHCP packets originating from outside
	// (e.g. DHCP multicast requests from other devices on the same network)
	"in_dhcp": 10,
	// App initiated HTTP requests towards the metadata server running in dom0
	"app_http": 11,
	// ICMPv6 traffic to and from an application
	"app_icmpv6": 12,
	// Traffic from Kubernetes pods to Kubernetes services.
	"kube_svc": 13,
	// Traffic directly forwarded between Kubernetes pods (not via services).
	"kube_pod": 14,
	// for kubernetes api-server
	"in_k3s": 15,
	// for kube Etcd
	"in_etcd": 16,
	// for flannel VxLan
	"in_flannel": 17,
	// for kube Metrics
	"in_metrics": 18,
	// for longhorn webhook
	"in_lhweb": 19,
	// for longhorn instance manager
	"in_lhinstmgr": 20,
	// for longhorn iscsi
	"in_iscsi": 21,
	// for longhorn nfs
	"in_nfs": 22,
	// for cluster advertise status
	"in_cluster_status": 23,
}

// GetConnmark : create connection mark corresponding to the given attributes.
func GetConnmark(appID uint8, aceID uint32, userAce, drop bool) uint32 {
	mark := uint32(appID) << 24
	mark |= aceID & AceIDMask
	if userAce {
		mark |= AceFromUser
	}
	if drop {
		mark |= AceDropAction
	}
	return mark
}

// ParseConnmark : parse attributes stored inside a connection mark.
func ParseConnmark(mark uint32) (appID uint8, aceID uint32, userAce, drop bool) {
	appID = uint8(mark >> 24)
	aceID = mark & AceIDMask
	userAce = (mark & AceFromUser) != 0
	drop = (mark & AceActionMask) == AceDropAction
	return
}
