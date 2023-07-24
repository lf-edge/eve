// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"syscall"

	"github.com/ti-mo/conntrack"
)

func conntrackToExportedEntry(flow *conntrack.Flow, capturedAt Timestamp) *ConntractEntry {
	if flow == nil {
		return nil
	}
	var tcpState TCPState
	if flow.TupleOrig.Proto.Protocol == syscall.IPPROTO_TCP {
		tcpState = TCPState(flow.ProtoInfo.TCP.State)
	}
	return &ConntractEntry{
		CapturedAt:  capturedAt,
		Status:      ConntrackStatus(flow.Status.Value),
		TCPState:    tcpState,
		Mark:        flow.Mark,
		AddrOrig:    conntrackToAddrTuple(flow.TupleOrig).toExportedAddrTuple(),
		AddrReply:   conntrackToAddrTuple(flow.TupleReply).toExportedAddrTuple(),
		PacketsSent: flow.CountersOrig.Packets,
		PacketsRecv: flow.CountersReply.Packets,
		BytesSent:   flow.CountersOrig.Bytes,
		BytesRecv:   flow.CountersReply.Bytes,
	}
}

func conntrackToAddrTuple(tuple conntrack.Tuple) addrTuple {
	return addrTuple{
		proto:   tuple.Proto.Protocol,
		srcIP:   tuple.IP.SourceAddress,
		dstIP:   tuple.IP.DestinationAddress,
		srcPort: tuple.Proto.SourcePort,
		dstPort: tuple.Proto.DestinationPort,
	}
}
