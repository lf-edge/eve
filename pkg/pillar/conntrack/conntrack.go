// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package with custom conntrack filters.

package conntrack

import (
	"net"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
)

// PortMapFilter : Custom filter to match on port-mapped flows
type PortMapFilter struct {
	Protocol     uint8  // udp, tcp, etc.
	ExternalPort uint16 // app external port
	InternalPort uint16 // app internal port
}

// MatchConntrackFlow : Implements CustomConntrackFilter interface to filter flows
func (f PortMapFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	match := true
	match = match && (flow.Forward.Protocol == f.Protocol)
	match = match && (f.ExternalPort == 0 || flow.Forward.DstPort == f.ExternalPort)
	match = match && (f.InternalPort == 0 || flow.Reverse.SrcPort == f.InternalPort)
	return match
}

// SrcIPFilter : Custom filter to match on source IP address, source port, protocol and mark
type SrcIPFilter struct {
	Log       *base.LogObject
	SrcIP     net.IP
	Proto     uint8
	SrcPort   uint16
	Mark      uint32
	MarkMask  uint32
	DebugShow bool
}

// MatchConntrackFlow : Implements CustomConntrackFilter interface to filter flows
func (f SrcIPFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	match := true
	match = match && (f.SrcIP.IsUnspecified() ||
		f.SrcIP.Equal(flow.Forward.SrcIP) || f.SrcIP.Equal(flow.Reverse.SrcIP))
	match = match && (f.Proto == 0 || flow.Forward.Protocol == f.Proto)
	match = match && (f.Mark&f.MarkMask == 0 || flow.Mark&f.MarkMask == f.Mark&f.MarkMask)
	match = match && (f.SrcPort == 0 ||
		flow.Forward.SrcPort == f.SrcPort || flow.Reverse.SrcPort == f.SrcPort)
	if match && f.DebugShow {
		f.Log.Noticef("flow matched for deletion: %v\n", flow)
	}
	return match
}
