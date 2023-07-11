// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nettrace

import (
	"context"
	"net"
	"sync"
	"syscall"

	"github.com/golang-design/lockfree"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/packetcap/go-pcap"
	"github.com/ti-mo/conntrack"
	"golang.org/x/net/bpf"
)

// packetCapturer captures packets for a network tracer (e.g. HTTPClient).
// It is not thread safe - should be used by the tracer exclusively.
type packetCapturer struct {
	tracer tracerWithPcap
	log    Logger
	opts   WithPacketCapture

	pendingPcap  *lockfree.Queue             // value: capturedPacket; waiting to be filtered
	filteredPcap map[string]*filteredPackets // key: ifName
}

type connIterCallback func(connAddr addrTuple, conntrack *conntrack.Flow) (stop bool)

// tracerWithPcap : interface that a tracer must implement to be compatible
// with packetCapturer.
type tracerWithPcap interface {
	networkTracer
	// Iterate over every traced not-yet-connected AF-INET socket.
	// conntrack can be nil (if not traced).
	iterNoConnSockets(connIterCallback)
	// Iterate over every traced connection.
	// conntrack can be nil (if not traced).
	iterConnections(connIterCallback)
}

// capturedPacket : packet captured as it was arriving or leaving through a given interface.
type capturedPacket struct {
	ifName string
	packet gopacket.Packet
}

// filteredPackets : packets captured and filtered for given interface.
type filteredPackets struct {
	ifName    string
	snapLen   uint32
	totalSize uint32
	truncated bool // maximum allowed size was reached, further packets will be dropped
	packets   []gopacket.Packet
}

type addrTuple struct {
	proto            uint8
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
}

func (at addrTuple) undefined() bool {
	return at.proto == 0 && at.srcIP == nil && at.dstIP == nil &&
		at.srcPort == 0 && at.dstPort == 0
}

func (at addrTuple) equal(at2 addrTuple) bool {
	return at.proto == at2.proto &&
		at.srcIP.Equal(at2.srcIP) && at.dstIP.Equal(at2.dstIP) &&
		at.srcPort == at2.srcPort && at.dstPort == at2.dstPort
}

func (at addrTuple) matchesPacket(packet addrTuple) bool {
	if at.proto != packet.proto {
		return false
	}
	if !at.withSrcAddr() {
		if (at.dstIP.Equal(packet.dstIP) && at.dstPort == packet.dstPort) ||
			(at.dstIP.Equal(packet.srcIP) && at.dstPort == packet.srcPort) {
			return true
		}
	} else {
		if (at.dstIP.Equal(packet.dstIP) && at.dstPort == packet.dstPort &&
			at.srcIP.Equal(packet.srcIP) && at.srcPort == packet.srcPort) ||
			(at.dstIP.Equal(packet.srcIP) && at.dstPort == packet.srcPort &&
				at.srcIP.Equal(packet.dstIP) && at.srcPort == packet.dstPort) {
			return true
		}
	}
	return false
}

func (at addrTuple) withSrcAddr() bool {
	return at.srcPort != 0 && at.srcIP != nil
}

func (at addrTuple) withDstAddr() bool {
	return at.dstPort != 0 && at.dstIP != nil
}

func (at addrTuple) toExportedAddrTuple() AddrTuple {
	return AddrTuple{
		SrcIP:   at.srcIP.String(),
		SrcPort: at.srcPort,
		DstIP:   at.dstIP.String(),
		DstPort: at.dstPort,
	}
}

func addrTupleFromConn(conn net.Conn) addrTuple {
	if conn == nil {
		return addrTuple{}
	}
	lTCPAddr, lIsTCP := conn.LocalAddr().(*net.TCPAddr)
	rTCPAddr, rIsTCP := conn.RemoteAddr().(*net.TCPAddr)
	if lIsTCP && rIsTCP {
		return addrTuple{
			proto:   syscall.IPPROTO_TCP,
			srcIP:   lTCPAddr.IP,
			dstIP:   rTCPAddr.IP,
			srcPort: uint16(lTCPAddr.Port),
			dstPort: uint16(rTCPAddr.Port),
		}
	}
	lUDPAddr, lIsUDP := conn.LocalAddr().(*net.UDPAddr)
	rUDPAddr, rIsUDP := conn.RemoteAddr().(*net.UDPAddr)
	if lIsUDP && rIsUDP {
		return addrTuple{
			proto:   syscall.IPPROTO_UDP,
			srcIP:   lUDPAddr.IP,
			dstIP:   rUDPAddr.IP,
			srcPort: uint16(lUDPAddr.Port),
			dstPort: uint16(rUDPAddr.Port),
		}
	}
	return addrTuple{}
}

func newPacketCapturer(forTracer tracerWithPcap, log Logger,
	opts WithPacketCapture) *packetCapturer {
	return &packetCapturer{
		tracer:       forTracer,
		log:          log,
		opts:         opts,
		pendingPcap:  lockfree.NewQueue(),
		filteredPcap: make(map[string]*filteredPackets),
	}
}

// Returns map ifname->pcap.
func (pc *packetCapturer) getPcap() (pcaps []PacketCapture) {
	pc.filterPcap()
	for ifName, pcap := range pc.filteredPcap {
		pcaps = append(pcaps, PacketCapture{
			InterfaceName:  ifName,
			SnapLen:        pcap.snapLen,
			Packets:        pcap.packets,
			Truncated:      pcap.truncated,
			WithTCPPayload: !pc.opts.TCPWithoutPayload,
		})
	}
	return pcaps
}

// Clear removes all captured packets (but the process of capturing packets is not stopped).
func (pc *packetCapturer) clearPcap() {
	pc.filteredPcap = make(map[string]*filteredPackets)
	var i uint64
	traceCount := pc.pendingPcap.Length()
	for i = 0; i < traceCount; i++ {
		_ = pc.pendingPcap.Dequeue()
	}
}

func (pc *packetCapturer) startPcap(ctx context.Context, wg *sync.WaitGroup) error {
	// tcpdump -dd 'icmp or arp or tcp or udp'
	withTCPPayload := []bpf.RawInstruction{
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
		{Op: 0x15, Jt: 0, Jf: 3, K: 0x00000800},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
		{Op: 0x15, Jt: 9, Jf: 0, K: 0x00000001},
		{Op: 0x15, Jt: 8, Jf: 7, K: 0x00000006},
		{Op: 0x15, Jt: 7, Jf: 0, K: 0x00000806},
		{Op: 0x15, Jt: 0, Jf: 7, K: 0x000086dd},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
		{Op: 0x15, Jt: 4, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 0, Jf: 2, K: 0x0000002c},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
		{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
		{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000011},
		{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
		{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
	}
	// tcpdump -dd 'icmp or arp or udp or (tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) == 0))'
	// Notes:
	//   - ip[2:2] is the Total Length of the IP packet
	//   - ((ip[0]&0xf)<<2) is Internet Header Length size of IP header
	//   - ((tcp[12]&0xf0)>>2) is the Data offset of the TCP Segment Header
	withoutTCPPayload := []bpf.RawInstruction{
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
		{Op: 0x15, Jt: 0, Jf: 20, K: 0x00000800},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
		{Op: 0x15, Jt: 25, Jf: 0, K: 0x00000001},
		{Op: 0x15, Jt: 24, Jf: 0, K: 0x00000011},
		{Op: 0x15, Jt: 0, Jf: 24, K: 0x00000006},
		{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000010},
		{Op: 0x2, Jt: 0, Jf: 0, K: 0x00000001},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x0000000e},
		{Op: 0x54, Jt: 0, Jf: 0, K: 0x0000000f},
		{Op: 0x64, Jt: 0, Jf: 0, K: 0x00000002},
		{Op: 0x7, Jt: 0, Jf: 0, K: 0x00000005},
		{Op: 0x60, Jt: 0, Jf: 0, K: 0x00000001},
		{Op: 0x1c, Jt: 0, Jf: 0, K: 0x00000000},
		{Op: 0x2, Jt: 0, Jf: 0, K: 0x00000005},
		{Op: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
		{Op: 0x50, Jt: 0, Jf: 0, K: 0x0000001a},
		{Op: 0x54, Jt: 0, Jf: 0, K: 0x000000f0},
		{Op: 0x74, Jt: 0, Jf: 0, K: 0x00000002},
		{Op: 0x7, Jt: 0, Jf: 0, K: 0x00000009},
		{Op: 0x60, Jt: 0, Jf: 0, K: 0x00000005},
		{Op: 0x1d, Jt: 7, Jf: 8, K: 0x00000000},
		{Op: 0x15, Jt: 6, Jf: 0, K: 0x00000806},
		{Op: 0x15, Jt: 0, Jf: 6, K: 0x000086dd},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
		{Op: 0x15, Jt: 3, Jf: 0, K: 0x00000011},
		{Op: 0x15, Jt: 0, Jf: 3, K: 0x0000002c},
		{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
		{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000011},
		{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
		{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
	}
	bpfFilter := withTCPPayload
	if pc.opts.TCPWithoutPayload {
		bpfFilter = withoutTCPPayload
	}
	pcapHandles := make([]*pcap.Handle, 0, len(pc.opts.Interfaces))
	for _, ifName := range pc.opts.Interfaces {
		// https://pkg.go.dev/github.com/google/gopacket/pcap#hdr-PCAP_Timeouts
		pcapHandle, err := pcap.OpenLive(
			ifName, int32(pc.opts.PacketSnaplen), true, 0, false)
		if err == nil {
			err = pcapHandle.SetRawBPFFilter(bpfFilter)
		}
		if err != nil {
			return err
		}
		pcapHandles = append(pcapHandles, pcapHandle)
	}
	for i, pcapHandle := range pcapHandles {
		wg.Add(1)
		go func(pcapHandle *pcap.Handle, ifName string) {
			defer wg.Done()
			defer pcapHandle.Close()
			packetSource := gopacket.NewPacketSource(
				pcapHandle, layers.LinkType(pcapHandle.LinkType()))
			packetSource.NoCopy = true
			packetsCh := packetSource.Packets()
			pc.log.Tracef(
				"nettrace: networkTracer id=%s: packet capture started for interface %s\n",
				pc.tracer.getTracerID(), ifName)
			for {
				select {
				case <-ctx.Done():
					pc.log.Tracef(
						"nettrace: networkTracer id=%s: packet capture stopped for interface %s\n",
						pc.tracer.getTracerID(), ifName)
					return
				case packet, more := <-packetsCh:
					if !more {
						pc.log.Tracef(
							"nettrace: networkTracer id=%s: packet capture closed for interface %s\n",
							pc.tracer.getTracerID(), ifName)
						return
					}
					pc.pendingPcap.Enqueue(capturedPacket{
						ifName: ifName,
						packet: packet,
					})
				}
			}
		}(pcapHandle, pc.opts.Interfaces[i])
	}
	return nil
}

// Returns true if we have enough information to precisely filter captured packets,
// without keeping any extra ones.
func (pc *packetCapturer) readyToFilterPcap() bool {
	var notReady bool
	iterCb := func(connAddr addrTuple, conntrack *conntrack.Flow) (stop bool) {
		if conntrack != nil {
			at := conntrackToAddrTuple(conntrack.TupleReply)
			if !at.withSrcAddr() || !at.withDstAddr() {
				// Wait with packet filtering until we learn how packets are being NATed.
				notReady = true
				return true
			}
			// This connection has complete (post-NAT) addr tuple, check the next one.
			return false
		}
		if !connAddr.withSrcAddr() || !connAddr.withDstAddr() {
			notReady = true
			return true
		}
		// This connection has complete (pre-NAT) addr tuple, check the next one.
		return false
	}
	pc.tracer.iterNoConnSockets(iterCb)
	if notReady {
		return false
	}
	pc.tracer.iterConnections(iterCb)
	return !notReady
}

// filterPcap should be called once in a while (preferably when readyToFilterPcap()
// returns true), so that we do not keep increasing memory usage with extra captured
// packets (not corresponding to traced connections).
func (pc *packetCapturer) filterPcap() {
	var i uint64
	traceCount := pc.pendingPcap.Length()
	for i = 0; i < traceCount; i++ {
		item := pc.pendingPcap.Dequeue()
		cp := item.(capturedPacket)
		packet := cp.packet
		ifName := cp.ifName
		if _, ok := pc.filteredPcap[ifName]; !ok {
			pc.filteredPcap[ifName] = &filteredPackets{
				ifName:  ifName,
				snapLen: pc.opts.PacketSnaplen,
			}
		}
		pcap := pc.filteredPcap[ifName]
		if pcap.truncated {
			// Max size was already reached, drop the packet.
			continue
		}
		keepPacket := pc.opts.IncludeARP && packet.Layer(layers.LayerTypeARP) != nil
		keepPacket = keepPacket || (pc.opts.IncludeICMP && packet.Layer(layers.LayerTypeICMPv4) != nil)
		keepPacket = keepPacket || (pc.opts.IncludeICMP && packet.Layer(layers.LayerTypeICMPv6) != nil)
		keepPacket = keepPacket || packetMatchesAnyConn(packet, pc.tracer.iterConnections)
		keepPacket = keepPacket || packetMatchesAnyConn(packet, pc.tracer.iterNoConnSockets)
		if keepPacket {
			packetSize := uint32(len(packet.Data()))
			if pcap.totalSize+packetSize > pc.opts.TotalSizeLimit {
				// Including this packet would exceed the maximum allowed pcap size.
				pcap.truncated = true
				continue
			}
			pcap.packets = append(pcap.packets, packet)
			pcap.totalSize += packetSize
		}
	}
}

func packetMatchesAnyConn(packet gopacket.Packet,
	connIter func(iterCb connIterCallback)) (match bool) {
	packetAddrs, supported := getPacketAddrs(packet)
	if !supported {
		return false
	}
	connIter(func(conn addrTuple, conntrack *conntrack.Flow) (stop bool) {
		if conntrack != nil {
			at := conntrackToAddrTuple(conntrack.TupleReply)
			if at.withSrcAddr() && at.withDstAddr() {
				if at.matchesPacket(packetAddrs) {
					match = true
					return true
				} else {
					return false
				}
			}
		}
		if conn.matchesPacket(packetAddrs) {
			match = true
			return true
		}
		return false
	})
	return match
}

func getPacketAddrs(packet gopacket.Packet) (at addrTuple, supported bool) {
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udpL, _ := layer.(*layers.UDP)
		at.srcPort = uint16(udpL.SrcPort)
		at.dstPort = uint16(udpL.DstPort)
		at.proto = syscall.IPPROTO_UDP
	} else if layer = packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcpL, _ := layer.(*layers.TCP)
		at.srcPort = uint16(tcpL.SrcPort)
		at.dstPort = uint16(tcpL.DstPort)
		at.proto = syscall.IPPROTO_TCP
	} else {
		return at, false
	}
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ipL, _ := layer.(*layers.IPv4)
		at.srcIP = ipL.SrcIP
		at.dstIP = ipL.DstIP
	} else if layer = packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ipL, _ := layer.(*layers.IPv6)
		at.srcIP = ipL.SrcIP
		at.dstIP = ipL.DstIP
	} else {
		return at, false
	}
	return at, true
}
