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
