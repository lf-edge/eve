// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Application flows recorded using netfilter Conntrack facility.

package nistate

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/bpf"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/packetcap/go-pcap"
	"github.com/vishvananda/netlink"
)

const (
	// Added on top of the protocol default values
	// (in pkg/dom0-ztools/rootfs/etc/sysctl.d/02-eve.conf).
	// When the remaining time for a flow drops below this value it is considered
	// as timeout-ed (despite intentionally not yet being removed by conntrack)
	// and ready to be collected by collectFlows.
	// IP flow collection interval should be less than this value,
	// so that the collector does not miss any flow (currently it is 2 minutes).
	// XXX We can log the same flow twice - isn't that a problem?
	conntrackFlowExtraTimeout int32 = 150 // in seconds

	// At maximum 125 FlowRec entries per single IPFlow.
	// Approximately 320 bytes per flow/dns.
	maxFlowPack int = 125

	// flowLogPrefix allows to filter logs specific to flow collecting
	// and packet sniffing.
	flowLogPrefix = LogAndErrPrefix + " (FlowStats)"

	// Even when flow logging is disabled, we continue recording application DNS requests
	// so that we can publish them in case the flow logging is later enabled.
	// To prevent the DNS record list from growing indefinitely, each record is retained
	// for a maximum of one day (a typical "long" TTL for DNS responses).
	dnsRecordRetentionTime = 24 * time.Hour

	// Statically configured IP address, detected using ARP snooping, is considered
	// valid until we do not see any more ARPs for this IP for more than 10 minutes.
	staticIPValidDuration = 10 * time.Minute
)

type capturedPacket struct {
	bridge NIBridge
	packet gopacket.Packet
	// If true then packet is nil and there will be no more packets
	// for this bridge.
	pcapClosed bool
}

type flowRec struct {
	types.FlowRec
	vif AppVIF
}

type dnsReq struct {
	types.DNSReq
	appIP net.IP
}

// Collect stats about active application IP flows using Netfilter conntrack.
func (lc *LinuxCollector) collectFlows() (flows []types.IPFlow) {
	var timeoutedFlows []flowRec
	var totalFlow int

	var flowlogEnabled bool
	for _, niInfo := range lc.nis {
		if niInfo.config.EnableFlowlog {
			flowlogEnabled = true
			break
		}
	}
	if !flowlogEnabled {
		return nil
	}

	// Get IPv4/v6 conntrack table flows
	protocols := [2]netlink.InetFamily{syscall.AF_INET, syscall.AF_INET6}
	for _, proto := range protocols {
		connT, err := netlink.ConntrackTableList(netlink.ConntrackTable, proto)
		if err != nil {
			lc.log.Errorf("%s: ContrackTableList failed: %v",
				flowLogPrefix, err)
			return nil
		}

		// Loop through and process timeout-ed flows.
		for _, entry := range connT {
			flow, skip := lc.convertConntrackToFlow(entry)
			if skip {
				continue
			}
			timeoutedFlows = append(timeoutedFlows, flow)
			totalFlow++
		}
	}

	// Sort flows by VIFs.
	for _, niInfo := range lc.nis {
		if !niInfo.config.EnableFlowlog {
			continue
		}
		var dnsReqs []dnsReq
		dnsReqs = append(dnsReqs, niInfo.ipv4DNSReqs...)
		dnsReqs = append(dnsReqs, niInfo.ipv6DNSReqs...)
		niInfo.ipv4DNSReqs = nil
		niInfo.ipv6DNSReqs = nil
		for _, vif := range niInfo.vifs {
			var sequence int
			ipFlow := types.IPFlow{
				Scope: types.FlowScope{
					AppUUID:        vif.App,
					NetAdapterName: vif.NetAdapterName,
					BrIfName:       niInfo.bridge.BrIfName,
					NetUUID:        niInfo.config.UUID,
				},
			}
			packIPFlow := func() {
				if sequence > 0 {
					ipFlow.Scope.Sequence = strconv.Itoa(sequence)
				}
				flows = append(flows, ipFlow)
				lc.log.Noticef(
					"%s: Collected IPFlow %+v with %d flows and %d DNS requests",
					flowLogPrefix, ipFlow.Scope, len(ipFlow.Flows), len(ipFlow.DNSReqs))
				ipFlow.Flows = nil
				ipFlow.DNSReqs = nil
				sequence++
			}
			for _, flowrec := range timeoutedFlows {
				if flowrec.vif.App != vif.App ||
					flowrec.vif.NetAdapterName != vif.NetAdapterName {
					continue
				}
				ipFlow.Flows = append(ipFlow.Flows, flowrec.FlowRec)
				if len(ipFlow.Flows) > maxFlowPack {
					packIPFlow()
				}
			}

			// Append DNS flows corresponding to this app.
			for _, dnsReq := range dnsReqs {
				if !vif.hasIP(dnsReq.appIP) {
					continue
				}
				ipFlow.DNSReqs = append(ipFlow.DNSReqs, dnsReq.DNSReq)
				if len(ipFlow.Flows)+len(ipFlow.DNSReqs) > maxFlowPack {
					packIPFlow()
				}
			}
			if len(ipFlow.Flows)+len(ipFlow.DNSReqs) > 0 {
				packIPFlow()
			}
		}
	}
	return flows
}

// Merge conntrack flow of two uni-directional stats into one
// bireditional flow recording.
func (lc *LinuxCollector) convertConntrackToFlow(
	entry *netlink.ConntrackFlow) (ipFlow flowRec, skip bool) {
	// For the current phase of implementation, we ignore the flowstats which
	// has not timed out yet.
	timeOut := int32(entry.TimeOut)
	if timeOut > conntrackFlowExtraTimeout {
		return ipFlow, true
	}
	appNum, aclID, userAce, drop := iptables.ParseConnmark(entry.Mark)
	// Only handle App related flows applied against user defined ACL rules or default
	// drop rules.
	if int(appNum) == 0 || (!userAce && !drop) {
		return ipFlow, true
	}
	vifs := lc.getVIFsByAppNum(int(appNum))
	if len(vifs) == 0 {
		return ipFlow, true
	}

	// ACL applied to this flow.
	if aclID != iptables.DefaultDropAceID {
		ipFlow.ACLID = int32(aclID)
	} else {
		ipFlow.ACLID = 0
	}
	if drop {
		ipFlow.Action = types.ACLActionDrop
	} else {
		ipFlow.Action = types.ACLActionAccept
	}

	// Flow timestamps.
	ipFlow.StartTime = int64(entry.TimeStart)
	timeoutedFor := time.Second * time.Duration(conntrackFlowExtraTimeout-timeOut)
	ipFlow.StopTime = time.Now().Add(-timeoutedFor).UnixNano()

	var forwSrcApp, forwDstApp, backSrcApp, backDstApp bool
	// Find out which one of the 4 IP addresses of the flow tuple matches
	// the App IPs.
	// Note that FlowRec.Flow.Src refers to application and FlowRec.Flow.Dst
	// refers to a remote endpoint, even for outside initiated flows, meaning
	// that "src" and "dst" is indeed a very confusing naming (already used
	// in EVE API therefore not easy to change).
	vif := lookupVIFByIP(entry.Forward.SrcIP, vifs)
	forwSrcApp = vif != nil
	if !forwSrcApp {
		vif = lookupVIFByIP(entry.Forward.DstIP, vifs)
		forwDstApp = vif != nil
		if !forwDstApp {
			vif = lookupVIFByIP(entry.Reverse.SrcIP, vifs)
			backSrcApp = vif != nil
			if !backSrcApp {
				vif = lookupVIFByIP(entry.Reverse.DstIP, vifs)
				backDstApp = vif != nil
			}
		}
	}

	if !forwSrcApp && !forwDstApp && !backSrcApp && !backDstApp {
		if entry.Forward.DstIP.IsMulticast() || entry.Forward.DstIP.Equal(net.IPv4bcast) {
			// Multicast/Broadcast packet sent from outside and forwarded to an app
			// through a switch NI, but app is not responding to this.
			// Just ignore this flow without any warning.
			return ipFlow, true
		}
		lc.log.Warnf("%s: Flow entry without app IP address, "+
			"appNum: %d, entry: %s", flowLogPrefix, appNum, entry.String())
		return ipFlow, true
	}

	// Assume we know which one of the 4 IP addresses is the app, then we know
	// which 'remote' IP address is in the flow tuple. Assign the Src/Dst and Ports
	// similar to RFC5130 to merge two bidirectional flow using the method of "Perimeter",
	// here we define the flow src is always the local App endpoint, the flow dst will
	// be the opposite endpoint.
	ipFlow.vif = vif.AppVIF
	ipFlow.Flow.Proto = int32(entry.Forward.Protocol)
	if forwSrcApp {
		// Src initiated flow, forward-src is the src, reverse-src is the flow dst
		ipFlow.Flow.Src = entry.Forward.SrcIP
		ipFlow.Flow.Dst = entry.Reverse.SrcIP
		ipFlow.Flow.SrcPort = int32(entry.Forward.SrcPort)
		ipFlow.Flow.DstPort = int32(entry.Reverse.SrcPort)
	} else if forwDstApp {
		// Non-NAT case, outside initiated flow, forward-dst is the src,
		// reverse-dst is the flow dst
		ipFlow.Flow.Src = entry.Forward.DstIP
		ipFlow.Flow.Dst = entry.Reverse.DstIP
		ipFlow.Flow.SrcPort = int32(entry.Forward.DstPort)
		ipFlow.Flow.DstPort = int32(entry.Reverse.DstPort)
		ipFlow.Inbound = true
	} else if backSrcApp {
		// NAT case, outside initiated flow, reverse-src is the src,
		// forward-src is the flow dst
		ipFlow.Flow.Src = entry.Reverse.SrcIP
		ipFlow.Flow.Dst = entry.Forward.SrcIP
		ipFlow.Flow.SrcPort = int32(entry.Reverse.SrcPort)
		ipFlow.Flow.DstPort = int32(entry.Forward.SrcPort)
		ipFlow.Inbound = true
	} else if backDstApp {
		// Non-NAT case, this should not happen, but reverse-dst is the src,
		// forward-dst is the flow dst
		ipFlow.Flow.Src = entry.Reverse.DstIP
		ipFlow.Flow.Dst = entry.Forward.DstIP
		ipFlow.Flow.SrcPort = int32(entry.Reverse.DstPort)
		ipFlow.Flow.DstPort = int32(entry.Forward.DstPort)
	}

	// If App initiated traffic, Forward is sending 'OUT',
	// otherwise Forward is receiving 'IN'.
	if ipFlow.Inbound {
		ipFlow.TxPkts = int64(entry.Reverse.Packets)
		ipFlow.TxBytes = int64(entry.Reverse.Bytes)
		ipFlow.RxPkts = int64(entry.Forward.Packets)
		ipFlow.RxBytes = int64(entry.Forward.Bytes)
	} else {
		ipFlow.TxPkts = int64(entry.Forward.Packets)
		ipFlow.TxBytes = int64(entry.Forward.Bytes)
		ipFlow.RxPkts = int64(entry.Reverse.Packets)
		ipFlow.RxBytes = int64(entry.Reverse.Bytes)
	}
	return ipFlow, false
}

// Sniff DNS traffic to capture domain name resolutions performed by apps.
// For switch network instances also capture DHCP and IPv6 DAD traffic to learn
// IP assignments for VIFs.
// This function is merely capturing packets and then sending them to runStateCollecting,
// so that all state collecting and processing happens from the main event loop
// (to simplify and avoid race conditions...).
func (lc *LinuxCollector) sniffDNSandDHCP(ctx context.Context, wg *sync.WaitGroup,
	br NIBridge, niType types.NetworkInstanceType, enableArpSnoop bool) {
	defer wg.Done()
	var (
		err         error
		snapshotLen int32 = 1280             // draft-madi-dnsop-udp4dns-00
		promiscuous       = true             // mainly for switched network
		timeout           = 10 * time.Second // collect enough packets in 10sec before processing
		filter            = "udp and port 53"
		// Raw instructions below are the compiled instructions of the filter above.
		// tcpdump -dd "udp and port 53"
		rawInstructions = []bpf.RawInstruction{
			{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
			{Op: 0x15, Jt: 0, Jf: 6, K: 0x000086dd},
			{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
			{Op: 0x15, Jt: 0, Jf: 15, K: 0x00000011},
			{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000036},
			{Op: 0x15, Jt: 12, Jf: 0, K: 0x00000035},
			{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000038},
			{Op: 0x15, Jt: 10, Jf: 11, K: 0x00000035},
			{Op: 0x15, Jt: 0, Jf: 10, K: 0x00000800},
			{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
			{Op: 0x15, Jt: 0, Jf: 8, K: 0x00000011},
			{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000014},
			{Op: 0x45, Jt: 6, Jf: 0, K: 0x00001fff},
			{Op: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
			{Op: 0x48, Jt: 0, Jf: 0, K: 0x0000000e},
			{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000035},
			{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000010},
			{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000035},
			{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
			{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
		}
		switched bool
		// XXX come back to handle TCP DNS snoop, more useful for zone transfer
		// https://github.com/google/gopacket/issues/236
	)
	if niType == types.NetworkInstanceTypeSwitch {
		switched = true
		filter = "(ip6 and icmp6 and ip6[40] == 135) or (udp and (port 53 or port 67 or port 546 or port 547))"
		// Raw instructions below are the compiled instructions of the filter above.
		// tcpdump -dd "(ip6 and icmp6 and ip6[40] == 135) or (udp and (port 53 or port 67 or port 546 or port 547)) or arp"
		if !enableArpSnoop {
			// If the user disables the ARP Snooping, the filter will omit the "or arp" above.
			// This configitem change may need a reboot of the device to take effect.
			rawInstructions = []bpf.RawInstruction{
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
				{Op: 0x15, Jt: 0, Jf: 16, K: 0x000086dd},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x15, Jt: 3, Jf: 0, K: 0x0000003a},
				{Op: 0x15, Jt: 0, Jf: 4, K: 0x0000002c},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 0, Jf: 28, K: 0x0000003a},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 25, Jf: 0, K: 0x00000087},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x15, Jt: 0, Jf: 24, K: 0x00000011},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 21, Jf: 0, K: 0x00000035},
				{Op: 0x15, Jt: 20, Jf: 0, K: 0x00000043},
				{Op: 0x15, Jt: 19, Jf: 0, K: 0x00000222},
				{Op: 0x15, Jt: 18, Jf: 0, K: 0x00000223},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000038},
				{Op: 0x15, Jt: 16, Jf: 13, K: 0x00000035},
				{Op: 0x15, Jt: 0, Jf: 16, K: 0x00000800},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
				{Op: 0x15, Jt: 0, Jf: 14, K: 0x00000011},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x45, Jt: 12, Jf: 0, K: 0x00001fff},
				{Op: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
				{Op: 0x48, Jt: 0, Jf: 0, K: 0x0000000e},
				{Op: 0x15, Jt: 8, Jf: 0, K: 0x00000035},
				{Op: 0x15, Jt: 7, Jf: 0, K: 0x00000043},
				{Op: 0x15, Jt: 6, Jf: 0, K: 0x00000222},
				{Op: 0x15, Jt: 5, Jf: 0, K: 0x00000223},
				{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000010},
				{Op: 0x15, Jt: 3, Jf: 0, K: 0x00000035},
				{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000043},
				{Op: 0x15, Jt: 1, Jf: 0, K: 0x00000222},
				{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000223},
				{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
				{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
			}
		} else {
			filter = filter + " or arp"
			rawInstructions = []bpf.RawInstruction{
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
				{Op: 0x15, Jt: 0, Jf: 16, K: 0x000086dd},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x15, Jt: 3, Jf: 0, K: 0x0000003a},
				{Op: 0x15, Jt: 0, Jf: 4, K: 0x0000002c},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 0, Jf: 29, K: 0x0000003a},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 26, Jf: 0, K: 0x00000087},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x15, Jt: 0, Jf: 25, K: 0x00000011},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000036},
				{Op: 0x15, Jt: 22, Jf: 0, K: 0x00000035},
				{Op: 0x15, Jt: 21, Jf: 0, K: 0x00000043},
				{Op: 0x15, Jt: 20, Jf: 0, K: 0x00000222},
				{Op: 0x15, Jt: 19, Jf: 0, K: 0x00000223},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000038},
				{Op: 0x15, Jt: 17, Jf: 13, K: 0x00000035},
				{Op: 0x15, Jt: 0, Jf: 15, K: 0x00000800},
				{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
				{Op: 0x15, Jt: 0, Jf: 15, K: 0x00000011},
				{Op: 0x28, Jt: 0, Jf: 0, K: 0x00000014},
				{Op: 0x45, Jt: 13, Jf: 0, K: 0x00001fff},
				{Op: 0xb1, Jt: 0, Jf: 0, K: 0x0000000e},
				{Op: 0x48, Jt: 0, Jf: 0, K: 0x0000000e},
				{Op: 0x15, Jt: 9, Jf: 0, K: 0x00000035},
				{Op: 0x15, Jt: 8, Jf: 0, K: 0x00000043},
				{Op: 0x15, Jt: 7, Jf: 0, K: 0x00000222},
				{Op: 0x15, Jt: 6, Jf: 0, K: 0x00000223},
				{Op: 0x48, Jt: 0, Jf: 0, K: 0x00000010},
				{Op: 0x15, Jt: 4, Jf: 0, K: 0x00000035},
				{Op: 0x15, Jt: 3, Jf: 0, K: 0x00000043},
				{Op: 0x15, Jt: 2, Jf: 0, K: 0x00000222},
				{Op: 0x15, Jt: 1, Jf: 2, K: 0x00000223},
				{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000806},
				{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
				{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
			}
		}
	}
	lc.log.Noticef("%s: Installing pcap on %s (bridge-num %d), "+
		"switched=%t, filter=%s", flowLogPrefix, br.BrIfName, br.BrNum, switched, filter)

	handle, err := pcap.OpenLive(br.BrIfName, snapshotLen, promiscuous, timeout, false)
	if err != nil {
		lc.log.Errorf(
			"%s: Cannot capture packets on %s (bridge-num %d): %v",
			flowLogPrefix, br.BrIfName, br.BrNum, err)
		return
	}
	defer handle.Close()

	err = handle.SetRawBPFFilter(rawInstructions)
	if err != nil {
		lc.log.Errorf("%s: Cannot install pcap filter [ %s ] on %s: %s",
			flowLogPrefix, filter, br.BrIfName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
	packetSource.NoCopy = true
	packetsCh := packetSource.Packets()
	for {
		select {
		case <-ctx.Done():
			lc.log.Noticef("%s: PCAP stopped on %s (bridge-num %d)",
				flowLogPrefix, br.BrIfName, br.BrNum)
			return
		case packet, more := <-packetsCh:
			if !more {
				lc.log.Noticef("%s: PCAP closed on %s (bridge-num %d)",
					flowLogPrefix, br.BrIfName, br.BrNum)
				// Inform the main event loop.
				lc.capturedPackets <- capturedPacket{
					bridge:     br,
					pcapClosed: true,
				}
				return
			}
			lc.capturedPackets <- capturedPacket{
				bridge: br,
				packet: packet,
			}
		}
	}
}

// Process DNS/DHCP/DAD packet captured from a network instance bridge.
// This is run from the main event loop (runStateCollecting).
func (lc *LinuxCollector) processCapturedPacket(
	capPacket capturedPacket) []VIFAddrsUpdate {
	br := capPacket.bridge
	niInfo, niExists := lc.nis[br.NI]
	if !niExists {
		lc.log.Warnf(
			"%s: Captured packet on unknown bridge %s (bridge-num %d)",
			flowLogPrefix, br.BrIfName, br.BrNum)
		return nil
	}
	if capPacket.pcapClosed {
		niInfo.ipv4DNSReqs = nil
		niInfo.ipv6DNSReqs = nil
		return nil
	}
	packet := capPacket.packet
	dnslayer := packet.Layer(layers.LayerTypeDNS)
	if packet.NetworkLayer() != nil {
		if niInfo.config.Type == types.NetworkInstanceTypeSwitch && dnslayer == nil {
			addrUpdates, isDhcp := lc.processDHCPPacket(niInfo, packet)
			if isDhcp {
				return addrUpdates
			}
			return lc.processDADProbe(niInfo, packet)
		}
		if dnslayer != nil {
			lc.processDNSPacketInfo(niInfo, packet)
		}
	} else if niInfo.config.Type == types.NetworkInstanceTypeSwitch &&
		packet.LinkLayer() != nil {
		addrUpdates := lc.processARPPacket(niInfo, packet)
		if len(addrUpdates) > 0 {
			return addrUpdates
		}
	}
	return nil
}

func (lc *LinuxCollector) processARPPacket(
	niInfo *niInfo, packet gopacket.Packet) (addrUpdates []VIFAddrsUpdate) {

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil
	}

	arp, _ := arpLayer.(*layers.ARP)
	if arp == nil {
		return nil
	}

	var vif *vifInfo
	var weAreSource bool
	var gotAddress []byte
	if arp.Operation == layers.ARPReply || arp.Operation == layers.ARPRequest {
		vif = niInfo.lookupVIFByGuestMAC(arp.DstHwAddress)
		if vif == nil {
			vif = niInfo.lookupVIFByGuestMAC(arp.SourceHwAddress)
			if vif != nil {
				weAreSource = true
			}
		}
		if vif == nil {
			return nil
		}
	} else {
		return nil
	}

	if weAreSource {
		gotAddress = arp.SourceProtAddress
	} else {
		gotAddress = arp.DstProtAddress
	}
	validUntil := time.Now().Add(staticIPValidDuration)
	update := vif.addIP(gotAddress, types.AddressSourceStatic, validUntil)
	if update != nil {
		addrUpdates = append(addrUpdates, *update)
	}
	return addrUpdates
}

// Used as a constant.
var broadcastMAC = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Process captured DHCP packets for switched network instances.
// Returns true if the packet being inspected is DHCP and intended for application(s)
// connected to the given network instance or else returns false.
// Additionally, returns the set of changes in IP address assignments as detected
// by processing this packet.
// This is run from the main event loop (runStateCollecting).
func (lc *LinuxCollector) processDHCPPacket(
	niInfo *niInfo, packet gopacket.Packet) (addrUpdates []VIFAddrsUpdate, isDHCP bool) {
	var foundDstMac, isBroadcast bool

	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		etherPkt := etherLayer.(*layers.Ethernet)
		if bytes.Compare(etherPkt.DstMAC, broadcastMAC) == 0 {
			// Some DHCP servers send replies with broadcast MAC address,
			// need to check those in payload to see if it's for an app.
			isBroadcast = true
		} else {
			foundDstMac = niInfo.lookupVIFByGuestMAC(etherPkt.DstMAC) != nil
		}
	}
	if !foundDstMac && !isBroadcast {
		// Packet not for applications connected to this NI.
		return nil, false
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	isIPv4 := ipLayer != nil
	if isIPv4 {
		// DHCP client will send discovery or request, server will send offer and Ack.
		// In the code we wait for the Reply from server with Ack to confirm the client's
		// IP address.
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			return nil, false
		}
		dhcpv4 := dhcpLayer.(*layers.DHCPv4)
		var isReplyAck bool
		var validUntil time.Time
		if dhcpv4.Operation == layers.DHCPOpReply {
			opts := dhcpv4.Options
			for _, opt := range opts {
				switch opt.Type {
				case layers.DHCPOptMessageType:
					if int(opt.Data[0]) == int(layers.DHCPMsgTypeAck) {
						isReplyAck = true
					}
				case layers.DHCPOptLeaseTime:
					leaseTimeSecs := binary.BigEndian.Uint32(opt.Data)
					validUntil = time.Now().Add(time.Duration(leaseTimeSecs) * time.Second)
				}
			}
		}

		if !isReplyAck {
			// This is indeed a DHCP packet but not the DHCP Reply type.
			return nil, true
		}
		if dhcpv4.YourClientIP.IsUnspecified() {
			// DHCP clients might use DHCPINFORM messages to obtain additional configuration
			// state that was not present in their lease binding.
			// In this case the RFC states that the DHCPACK message returned by server
			// should have the yiaddr field (YourClientIP) unset.
			// In order to not lose information about the allocated app IP address
			// we therefore skip over DHCPACK messages with unspecified client IP.
			//
			// For more information see:
			// https://datatracker.ietf.org/doc/html/rfc2131#section-4.3.5
			// https://datatracker.ietf.org/doc/html/draft-ietf-dhc-dhcpinform-clarify
			return nil, true
		}

		vif := niInfo.lookupVIFByGuestMAC(dhcpv4.ClientHWAddr)
		if vif == nil {
			return nil, true
		}
		update := vif.addIP(dhcpv4.YourClientIP, types.AddressSourceExternalDHCP,
			validUntil)
		if update != nil {
			addrUpdates = append(addrUpdates, *update)
		}
		return addrUpdates, true
	}

	// This is IPv6 packet.
	// XXX Need to come back to handle IPv6 properly, including:
	//  - each MAC can have both IPv4 and IPv6 addresses
	//  - IPv6 can be stateful with DHCPv6 or stateless with autoconfig with RS/RA/etc.
	//  - IPv6 can be link-local, global scope and rfc 4941 with many temporary addresses
	//    which we don't know which one it will use and timeout
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcpLayer == nil {
		return nil, false
	}
	dhcpv6 := dhcpLayer.(*layers.DHCPv6)
	//  We are only interested in DHCPv6 Reply packets. Skip others.
	if dhcpv6.MsgType != layers.DHCPv6MsgTypeReply {
		// This is indeed a DHCP packet but not the DHCP Reply type.
		return nil, true
	}
	var vif *vifInfo
	var validUntil time.Time
	for _, opt := range dhcpv6.Options {
		switch opt.Code {
		case layers.DHCPv6OptClientID:
			clientOption := &layers.DHCPv6DUID{}
			clientOption.DecodeFromBytes(opt.Data)
			vif = niInfo.lookupVIFByGuestMAC(clientOption.LinkLayerAddress)
		case layers.DHCPv6OptIAAddr:
			// Parse IA Address option to get valid-lifetime.
			if len(opt.Data) >= 24 {
				// Valid-lifetime is at offset 20-23 (4 bytes).
				validLifetimeSecs := binary.BigEndian.Uint32(opt.Data[20:24])
				validUntil = time.Now().Add(time.Duration(validLifetimeSecs) * time.Second)
			}
		}
	}
	if vif == nil {
		return nil, true
	}
	update := vif.addIP(dhcpv6.LinkAddr, types.AddressSourceExternalDHCP,
		validUntil)
	if update != nil {
		addrUpdates = append(addrUpdates, *update)
	}
	return addrUpdates, true
}

// Process captured ICMPv6 NS packet for a switched network instance to learn
// about IPv6 assignments for apps connected to this NI.
// Returns the set of changes in IP address assignments as detected
// by processing this packet.
func (lc *LinuxCollector) processDADProbe(
	niInfo *niInfo, packet gopacket.Packet) (addrUpdates []VIFAddrsUpdate) {
	var vif *vifInfo
	if etherLayer := packet.Layer(layers.LayerTypeEthernet); etherLayer != nil {
		etherPkt := etherLayer.(*layers.Ethernet)
		vif = niInfo.lookupVIFByGuestMAC(etherPkt.SrcMAC)
	}
	if vif == nil {
		return
	}
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		return
	}
	ip6 := ip6Layer.(*layers.IPv6)
	// We are looking for ICMPv6 Neighbor solicitation packet that
	// tries to find if the address calculated locally is a duplicate.
	// Such packets have a source IP of all zeroes.
	if !ip6.SrcIP.IsUnspecified() {
		return
	}
	icmp6Layer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if icmp6Layer == nil {
		return
	}
	icmp6 := icmp6Layer.(*layers.ICMPv6NeighborSolicitation)
	// DAD is not performed periodically, therefore we should not remove the IP address
	// from the list after some time duration just because we have not seen another
	// ICMPv6 NS packet.
	undefinedValidity := time.Time{}
	update := vif.addIP(icmp6.TargetAddress, types.AddressSourceSLAAC,
		undefinedValidity)
	if update != nil {
		addrUpdates = append(addrUpdates, *update)
	}
	return addrUpdates
}

// Process a DNS response packet to collect and publish flow stats for domain name
// resolutions performed by apps.
func (lc *LinuxCollector) processDNSPacketInfo(
	niInfo *niInfo, packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)
	if len(dns.Questions) == 0 || len(dns.Answers) == 0 {
		return
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var dstIP net.IP
	if ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		dstIP = ip.DstIP
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			dstIP = ipv6.DstIP
		}
	}
	var checkedProto, isIPv4 bool
	// Do not keep recording of a DNS request for more than a day.
	currentTime := time.Now().UnixNano()
	keepDNSRecord := func(req dnsReq) bool {
		return time.Duration(currentTime-req.RequestTime) <= dnsRecordRetentionTime
	}
	// Note that DNS requests with multiple questions and nameservers supporting
	// them is very rare and pretty much nonexistent (too much ambiguity).
	dnsQ := dns.Questions[0]
	dnsReq := dnsReq{
		DNSReq: types.DNSReq{
			HostName:    string(dnsQ.Name),
			RequestTime: currentTime,
		},
		appIP: dstIP,
	}
	for _, dnsA := range dns.Answers {
		if dnsA.Type != layers.DNSTypeA && dnsA.Type != layers.DNSTypeAAAA {
			continue
		}
		if len(dnsA.IP) != 0 {
			if !checkedProto {
				// IP version is determined based on the first answer.
				isIPv4 = dnsA.IP.To4() != nil
				checkedProto = true
			}
			dnsReq.Addrs = append(dnsReq.Addrs, dnsA.IP)
		}
	}
	if len(dnsReq.Addrs) > 0 {
		if isIPv4 {
			niInfo.ipv4DNSReqs = append(niInfo.ipv4DNSReqs, dnsReq)
			niInfo.ipv4DNSReqs = generics.FilterList(niInfo.ipv4DNSReqs, keepDNSRecord)
		} else {
			niInfo.ipv6DNSReqs = append(niInfo.ipv6DNSReqs, dnsReq)
			niInfo.ipv6DNSReqs = generics.FilterList(niInfo.ipv6DNSReqs, keepDNSRecord)
		}
	}
}

func lookupVIFByIP(ip net.IP, vifs []*vifInfo) *vifInfo {
	for _, vif := range vifs {
		if vif.hasIP(ip) {
			return vif
		}
	}
	return nil
}
