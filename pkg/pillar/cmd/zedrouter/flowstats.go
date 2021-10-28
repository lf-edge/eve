// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Flow Statistics collection from IPtable Conntrack facility

package zedrouter

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/lf-edge/eve/pkg/pillar/types"
	pcap "github.com/packetcap/go-pcap"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
)

type flowStats struct {
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Proto       uint8
	SendPkts    uint64
	SendBytes   uint64
	RecvPkts    uint64
	RecvBytes   uint64
	TimeStart   int64
	TimeStop    int64
	TimeOut     uint32
	aclNum      uint32
	appNum      uint8
	drop        bool
	AppInitiate bool
	IsTimeOut   bool
	foundApp    bool
	dbg1        int
	dbg2        int
}

type aclAttr struct {
	aclNum    uint32
	tableName string
	aclName   string
	chainName string
	bridge    string
	intfname  string // App virtual interface name assigned by cloud template
}

type bridgeAttr struct {
	bridge  string
	netUUID uuid.UUID
}

type appInfo struct {
	ipaddr    net.IP
	intf      string
	localintf string
}

type networkAttrs struct {
	ipaclattr map[int]map[int]aclAttr // appNum, ACLNum, acl attributes
	appIPinfo map[int][]appInfo       // appNum, IP addresses/intfs (may belong to diff bridges)
	intfAddrs []net.Addr              // device interface addresses
	bnNet     map[string]bridgeAttr   // mainly need to range all the bridge interfaces
	appNet    map[int]uuid.UUID       // max 256 apps
}

type dnsEntry struct {
	AppIP      net.IP    // DNS message replies to
	DomainName string    // Domain Name
	TimeStamp  time.Time // time of the DNS server reply
	isIPv4     bool      // returned IP is protocol IPv4
	ANCount    uint16    // number of IP addresses in reply
	Answers    []net.IP  // list of IP addresses
}

const (
	maxBridgeNumber int   = 256
	timeoutSec      int32 = 150  // less than 150 sec, consider done (make sure to update 01-eve.conf in pkg/dom0-ztools)
	maxFlowPack     int   = 125  // approximate 320 bytes per flow/dns, got an assert in zedagent when size was 241
	flowStaleSec    int64 = 1800 // 30 min not touched, the publication will be removed
)

type dnsSys struct {
	sync.Mutex
	Done        chan bool
	channelOpen bool
	Snoop       []dnsEntry
}

var loopcount int // XXX debug

var dnssys [maxBridgeNumber]dnsSys // per bridge DNS records for the collection period
var nilUUID uuid.UUID
var broadcastMAC = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// FlowStatsCollect : Timer fired to collect iptable flow stats
func FlowStatsCollect(ctx *zedrouterContext) {
	var instData networkAttrs
	var timeOutTuples []flowStats
	var totalFlow int

	instData.ipaclattr = make(map[int]map[int]aclAttr) // App-ID/ACL-Num/aclAttr table
	instData.appIPinfo = make(map[int][]appInfo)
	instData.bnNet = make(map[string]bridgeAttr) // borrow the aclAttr for intf attributes
	instData.appNet = make(map[int]uuid.UUID)

	IntfAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Errorf("error in getting addresses\n")
		return
	}
	instData.intfAddrs = IntfAddrs

	checkAppAndACL(ctx, &instData)

	// Get IPv4/v6 conntrack table flows
	Protocols := [2]netlink.InetFamily{syscall.AF_INET, syscall.AF_INET6}
	for _, proto := range Protocols {
		connT, err := netlink.ConntrackTableList(netlink.ConntrackTable, proto)
		if err != nil {
			log.Errorf("FlowStats(%d): ContrackTableList", proto)
			return
		}

		log.Tracef("***FlowStats(%d): size of the flows %d", proto, len(connT))

		for _, entry := range connT { // loop through and process current timedout flow collection
			flowTuple := flowMergeProcess(entry, instData)
			// flowTuple := FlowMergeTuple(entry, instData, ipToName)
			if flowTuple.IsTimeOut == false || flowTuple.foundApp == false {
				continue
			}

			timeOutTuples = append(timeOutTuples, flowTuple)
			totalFlow++
		}
	}

	log.Tracef("FlowStats ++ Total timedout flows %d, loopcount debug %d\n", totalFlow, loopcount)
	loopcount++

	// per app/bridge packing flow stats to be uploaded
	for bnx := range instData.bnNet {
		// obtain DNS entries recorded since the last flow collection
		bnNum, err := bridgeStrToNum(ctx, bnx)
		if err != nil {
			log.Error(err)
			continue
		}
		dnssys[bnNum].Lock()
		dnsEntries := dnssys[bnNum].Snoop
		dnssys[bnNum].Snoop = nil
		dnssys[bnNum].Unlock()

		for appIdx := range instData.appNet {
			var sequence, flowIdx int

			// fill in the partial scope information, later the aclNum and aclAttr will decide
			// if we have a match in this flow into app/bridge scope
			scope := types.FlowScope{
				UUID:      instData.appNet[appIdx],
				Localintf: instData.bnNet[bnx].bridge,
				NetUUID:   instData.bnNet[bnx].netUUID,
			}
			flowdata := types.IPFlow{
				Scope: scope,
			}

			log.Tracef("FlowStats: bnx=%s, appidx %d\n", bnx, appIdx)
			// temp print out the flow "tuple" and stats per app/bridge
			for i, tuple := range timeOutTuples { // search for flowstats by bridge
				var aclattr aclAttr
				var aclNum int
				var aclaction types.ACLActionType

				appN := tuple.appNum
				if int(appN) != appIdx { // allow non-App flows to be uploaded
					//log.Functionf("FlowStats: appN %d, appIdx %d not match", appN, appIdx)
					continue
				}

				if tuple.aclNum != defaultDropAceID {
					tmpMap := instData.ipaclattr[int(appN)]
					if tmpMap != nil {
						if _, ok := tmpMap[int(tuple.aclNum)]; !ok {
							log.Tracef("FlowStats: == can not get acl map with aclN, should not happen appN %d, aclN %d; %s\n",
								appN, tuple.aclNum, tuple.String())
							continue
						}
						aclattr = tmpMap[int(tuple.aclNum)]
					} else {
						log.Tracef("FlowStats: == can't get acl map with appN, should not happen, appN %d, aclN %d; %s\n",
							appN, tuple.aclNum, tuple.String())
						continue
					}
					if aclattr.aclNum == 0 {
						log.Tracef("FlowStats: == aclN zero in attr, appN %d, aclN %d; %s\n", appN, tuple.aclNum, tuple.String())
						// some debug info
						continue
					}

					if aclattr.bridge != bnx {
						log.Tracef("FlowStats: == bridge name not match %s, %s\n", bnx, aclattr.bridge)
						continue
					}
					scope.Intf = aclattr.intfname // App side DomU internal interface name
					if tuple.drop {
						aclaction = types.ACLActionDrop
					} else {
						aclaction = types.ACLActionAccept
					}
					aclNum = int(aclattr.aclNum)
				} else {
					// default drop ACE
					appinfo := flowGetAppInfo(tuple, instData.appIPinfo[appIdx])
					if appinfo.localintf != bnx {
						continue
					}
					scope.Intf = appinfo.intf
					aclaction = types.ACLActionDrop
					aclNum = 0
				}

				// temp print out log for the flow
				log.Tracef("FlowStats [%d]: on bn%d %s\n", i, bnNum, tuple.String()) // just print for now

				flowtuple := types.IPTuple{
					Src:     tuple.SrcIP,
					Dst:     tuple.DstIP,
					SrcPort: int32(tuple.SrcPort),
					DstPort: int32(tuple.DstPort),
					Proto:   int32(tuple.Proto),
				}
				flowrec := types.FlowRec{
					Flow:      flowtuple,
					Inbound:   !tuple.AppInitiate,
					ACLID:     int32(aclNum),
					Action:    aclaction,
					StartTime: tuple.TimeStart,
					StopTime:  tuple.TimeStop,
					TxBytes:   int64(tuple.SendBytes),
					TxPkts:    int64(tuple.SendPkts),
					RxBytes:   int64(tuple.RecvBytes),
					RxPkts:    int64(tuple.RecvPkts),
				}

				flowdata.Flows = append(flowdata.Flows, flowrec)
				flowIdx++
				if flowIdx > maxFlowPack {
					flowPublish(ctx, &flowdata, &sequence, &flowIdx)
				}
			}

			var dnsrec [2]map[string]dnsEntry
			dnsrec[0] = make(map[string]dnsEntry) // store IPv4 addresses from dns
			dnsrec[1] = make(map[string]dnsEntry) // store IPv6 addresses from dns

			// select dns request/replies corresponding to this app
			for _, dnsdata := range dnsEntries {
				if !checkAppIPAddr(instData.appIPinfo[appIdx], dnsdata.AppIP) {
					continue
				}
				// unique by domain name, latest reply overwrite previous ones
				if dnsdata.isIPv4 {
					dnsrec[0][dnsdata.DomainName] = dnsdata
				} else {
					dnsrec[1][dnsdata.DomainName] = dnsdata
				}
			}

			// append dns records into the flow data
			for idx := range dnsrec {
				for _, dnsRec := range dnsrec[idx] {
					// temp print out all unique dns replies for the bridge/app
					log.Tracef("!!FlowStats: DNS time %v, domain %s, appIP %v, count %d, Answers %v",
						dnsRec.TimeStamp, dnsRec.DomainName, dnsRec.AppIP, dnsRec.ANCount, dnsRec.Answers)

					dnsrec := types.DNSReq{
						HostName:    dnsRec.DomainName,
						Addrs:       dnsRec.Answers,
						RequestTime: dnsRec.TimeStamp.UnixNano(),
					}
					flowdata.DNSReqs = append(flowdata.DNSReqs, dnsrec)
					flowIdx++
					if flowIdx > maxFlowPack {
						flowPublish(ctx, &flowdata, &sequence, &flowIdx)
					}
				}
			}

			// flow record done for the bridge/app
			// publish the flow data (per app/bridge) and sequence (for size limit) to zedagent now
			flowPublish(ctx, &flowdata, &sequence, &flowIdx)
		}
	}
	// check and remove stale flowlog publications
	checkFlowUnpublish(ctx)
}

// conntrack flow of two uni-directional stats into one
// bireditional flow stats
func flowMergeProcess(entry *netlink.ConntrackFlow, instData networkAttrs) flowStats {
	var ipFlow flowStats
	var forwSrcApp, forwDstApp, backSrcApp, backDstApp bool
	var AppNum int

	// for the current phase of implementation, we ignore the flowstats which has not timed out yet
	ipflowTimeOut := int32(entry.TimeOut)
	if ipflowTimeOut > timeoutSec {
		return ipFlow
	}
	ipFlow.appNum, ipFlow.aclNum, ipFlow.drop = parseConnmark(entry.Mark)
	AppNum = int(ipFlow.appNum)
	if AppNum == 0 { // only handle App related flow stats, Mark set needs to zero out the app field if not app related
		return ipFlow
	}

	ipFlow.TimeStart = int64(entry.TimeStart)
	// the flow timed out timeoutSec - entry.TimeOut seconds before
	timeStop := time.Now().Add(-(time.Second * time.Duration(timeoutSec-int32(entry.TimeOut))))
	ipFlow.TimeStop = timeStop.UnixNano()
	ipFlow.TimeOut = entry.TimeOut
	ipFlow.Proto = entry.Forward.Protocol
	ipFlow.IsTimeOut = true

	// Assume the App has an assigned IP address(es) first
	// the instData.appIPinfo has the IP addresses of an App, we want to know
	// which one of the 4 IP addresses of the flow tuple matches the App IPs
	if len(instData.appIPinfo[AppNum]) > 0 {
		ipFlow.dbg1 = 1
		forwSrcApp = checkAppIPAddr(instData.appIPinfo[AppNum], entry.Forward.SrcIP)
		if forwSrcApp == false {
			ipFlow.dbg1 = 2
			forwDstApp = checkAppIPAddr(instData.appIPinfo[AppNum], entry.Forward.DstIP)
			if forwDstApp == false {
				ipFlow.dbg1 = 3
				backSrcApp = checkAppIPAddr(instData.appIPinfo[AppNum], entry.Reverse.SrcIP)
				if backSrcApp == false {
					ipFlow.dbg1 = 4
					backDstApp = checkAppIPAddr(instData.appIPinfo[AppNum], entry.Reverse.DstIP)
				} else {
					ipFlow.dbg1 = 5 // XXX
				}
			}
		}
	}

	// if failed to get an App IP to match flow tuple, find remote from Intf subnets
	// and reversely getting the 'app' IP
	// Find which endpoint of the flow is NOT on my IP subnets, assume that is the
	// far end, then the reverse flow other end SHOULD be the App on the box
	if !forwSrcApp && !forwDstApp && !backSrcApp && !backDstApp {
		if len(instData.intfAddrs) > 0 {
			ipFlow.dbg1 = 6
			if !isInMySubnets(entry.Forward.SrcIP, instData.intfAddrs) { // forw src is remote endpoint
				ipFlow.dbg1 = 7
				// in this case, if the forw.src is remote, then assume the reverse.src is the app
				backSrcApp = true
			} else if !isInMySubnets(entry.Reverse.SrcIP, instData.intfAddrs) {
				ipFlow.dbg1 = 8
				forwSrcApp = true
			} else if !isInMySubnets(entry.Forward.DstIP, instData.intfAddrs) {
				ipFlow.dbg1 = 9
				backDstApp = true
			} else if !isInMySubnets(entry.Reverse.DstIP, instData.intfAddrs) {
				ipFlow.dbg1 = 10
				forwDstApp = true
			}
		}
	}

	// Assume we know which one of the 4 IP addresses is the app, then we know
	// which 'remote' IP address is in the flow tuple. Assign the Src/Dst and Ports
	// similar to RFC5130 to merge two bidirectional flow using the method of "Perimeter",
	// here we define the flow src is always the local App endpoint, the flow dst will
	// be the opposite endpoing.
	if forwSrcApp {
		// src initiated flow, forw-src is the src, rev-src is the flow dst
		ipFlow.dbg2 = 1
		ipFlow.SrcIP = entry.Forward.SrcIP
		ipFlow.DstIP = entry.Reverse.SrcIP
		ipFlow.SrcPort = entry.Forward.SrcPort
		ipFlow.DstPort = entry.Reverse.SrcPort
		ipFlow.AppInitiate = true
	} else if forwDstApp {
		// non-NAT case, outside initiated flow, forw-dst is the src, rev-dst is the flow dst
		ipFlow.dbg2 = 2
		ipFlow.SrcIP = entry.Forward.DstIP
		ipFlow.DstIP = entry.Reverse.DstIP
		ipFlow.SrcPort = entry.Forward.DstPort
		ipFlow.DstPort = entry.Reverse.DstPort
	} else if backSrcApp {
		// NAT case, outside initiated flow, rev-src is the src, forw-src is the flow dst
		ipFlow.dbg2 = 3
		ipFlow.DstIP = entry.Forward.SrcIP
		ipFlow.SrcIP = entry.Reverse.SrcIP
		ipFlow.DstPort = entry.Forward.SrcPort
		ipFlow.SrcPort = entry.Reverse.SrcPort
	} else if backDstApp {
		// non-NAT case, this should not happen, but rev-dst is the src, forw-dst is the flow dst
		ipFlow.dbg2 = 4
		ipFlow.SrcIP = entry.Reverse.DstIP
		ipFlow.DstIP = entry.Forward.DstIP
		ipFlow.SrcPort = entry.Reverse.DstPort
		ipFlow.DstPort = entry.Forward.DstPort
		ipFlow.AppInitiate = true
	} else { // if we can not find our App endpoint is part of the flow, something is wrong
		ipFlow.dbg2 = 5
		log.Tracef("FlowStats: flow entry can not locate app IP address, appNum %d, %s", AppNum, entry.String())
		return ipFlow
	}

	ipFlow.foundApp = true
	// If App initiated traffic, forw is sending 'OUT', otherwise forw is receiving 'IN'
	if ipFlow.AppInitiate {
		ipFlow.SendPkts = entry.Forward.Packets
		ipFlow.SendBytes = entry.Forward.Bytes
		ipFlow.RecvPkts = entry.Reverse.Packets
		ipFlow.RecvBytes = entry.Reverse.Bytes
	} else {
		ipFlow.SendPkts = entry.Reverse.Packets
		ipFlow.SendBytes = entry.Reverse.Bytes
		ipFlow.RecvPkts = entry.Forward.Packets
		ipFlow.RecvBytes = entry.Forward.Bytes
	}
	return ipFlow
}

func flowGetAppInfo(tuple flowStats, appinformation []appInfo) appInfo {
	var appinfo appInfo
	for _, info := range appinformation {
		if info.ipaddr.Equal(tuple.SrcIP) || info.ipaddr.Equal(tuple.DstIP) {
			appinfo = info
			return appinfo
		}
	}
	return appinfo
}

func checkAppIPAddr(appinformation []appInfo, entryIP net.IP) bool {
	for _, appinfo := range appinformation {
		if appinfo.ipaddr.Equal(entryIP) {
			return true
		}
	}
	return false
}

// check to see if the IP address is on my local subnets
func isInMySubnets(faddr net.IP, addrList []net.Addr) bool {
	for _, address := range addrList {
		if ipnet, ok := address.(*net.IPNet); ok {
			if ipnet.Contains(faddr) {
				return true
			}
		}
	}
	return false
}

// print the FlowTuple entries
func (s *flowStats) String() string {
	tstart := time.Unix(0, s.TimeStart)
	tout := int32(s.TimeOut)
	return fmt.Sprintf("TS %v, TO %d(sec), proto %d src=%s dst=%s sport=%d dport=%d, snd=pkts/bytes %d/%d rcv=pkts/bytes %d/%d app-init %v, appNum %d, aclnum 0x%x",
		tstart, tout, s.Proto, s.SrcIP, s.DstIP, s.SrcPort, s.DstPort, s.SendPkts, s.SendBytes,
		s.RecvPkts, s.RecvBytes, s.AppInitiate, s.appNum, s.aclNum)
}

// for each flow collection run, this function compiles a number of
// caches for App IP addresses, App List, Bridge List and attributes, and
// app/aclnum indexed acl information
func checkAppAndACL(ctx *zedrouterContext, instData *networkAttrs) {
	pub := ctx.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		appID := status.UUIDandVersion.UUID
		for i, ulStatus := range status.UnderlayNetworkList {
			log.Tracef("===FlowStats: (index %d) AppNum %d, VifInfo %v, IP addr %v, Hostname %s\n",
				i, status.AppNum, ulStatus.VifInfo, ulStatus.AllocatedIPv4Addr, ulStatus.HostName)

			ulconfig := ulStatus.UnderlayNetworkConfig
			// build an App-IPaddress/intfs cache indexed by App-number
			tmpAppInfo := appInfo{
				ipaddr:    net.ParseIP(ulStatus.AllocatedIPv4Addr),
				intf:      ulStatus.Name,
				localintf: ulStatus.Bridge,
			}
			netstatus := lookupNetworkInstanceStatus(ctx, ulconfig.Network.String())
			if netstatus != nil {
				if netstatus.Type == types.NetworkInstanceTypeSwitch {
					if _, ok := netstatus.IPAssignments[ulStatus.Mac]; ok {
						tmpAppInfo.ipaddr = net.IP{}
						addrs := netstatus.IPAssignments[ulStatus.Mac]
						tmpAppInfo.ipaddr = addrs.IPv4Addr
						log.Tracef("===FlowStats: switchnet, get ip %v\n", tmpAppInfo.ipaddr)
					}
				}
			}
			instData.appIPinfo[status.AppNum] = append(instData.appIPinfo[status.AppNum], tmpAppInfo)

			// Fill in the bnNet indexed by bridge-name, used for loop through bridges, and Scope
			intfAttr := bridgeAttr{
				bridge:  ulStatus.Bridge,
				netUUID: ulconfig.Network,
			}
			instData.bnNet[ulStatus.Bridge] = intfAttr

			// build an App list cache, used for loop through all the Apps
			if instData.appNet[status.AppNum] == nilUUID {
				instData.appNet[status.AppNum] = status.UUIDandVersion.UUID
				log.Tracef("===FlowStats: appNet appNum %d, uuid %v\n", status.AppNum, instData.appNet[status.AppNum])
			}

			// build an acl cache indexed by app/aclnum, from flow MARK, we can get this aclAttr info
			tmpMap := instData.ipaclattr[status.AppNum]
			if tmpMap == nil {
				tmpMap := make(map[int]aclAttr)
				instData.ipaclattr[status.AppNum] = tmpMap
			}
			rules := getNetworkACLRules(ctx, appID, ulStatus.Name)
			for _, rule := range rules.ACLRules {
				if (rule.IsUserConfigured == false || rule.IsMarkingRule == true) &&
					rule.IsDefaultDrop == false {
					// only include user defined rules and default drop rules
					continue
				}

				var tempAttr aclAttr
				tempAttr.aclNum = uint32(rule.RuleID)
				tempAttr.chainName = rule.ActionChainName
				tempAttr.aclName = rule.RuleName
				tempAttr.tableName = rule.Table
				tempAttr.bridge = ulStatus.Bridge
				tempAttr.intfname = ulStatus.Name

				if _, ok := instData.ipaclattr[status.AppNum][int(rule.RuleID)]; !ok { // fake j as the aclNUM
					instData.ipaclattr[status.AppNum][int(rule.RuleID)] = tempAttr
				} else {
					preAttr := instData.ipaclattr[status.AppNum][int(rule.RuleID)]
					// the the entry exist, and already has the aclNum and bridge name, skip
					if preAttr.aclNum == 0 || preAttr.bridge == "" {
						instData.ipaclattr[status.AppNum][int(rule.RuleID)] = tempAttr
					}
				}
			}
		}
	}
}

func flowPublish(ctx *zedrouterContext, flowdata *types.IPFlow, seq, idx *int) {
	var flowKey string
	scope := flowdata.Scope
	if *seq > 0 {
		scope.Sequence = strconv.Itoa(*seq)
	}
	flowKey = scope.UUID.String() + scope.NetUUID.String() + scope.Sequence
	ctx.flowPublishMap[flowKey] = time.Now()

	ctx.pubAppFlowMonitor.Publish(flowKey, *flowdata)
	log.Functionf("FlowStats: publish to zedagent: total records %d, sequence %d\n", *idx, *seq)
	*seq++
	flowdata.Flows = nil
	flowdata.DNSReqs = nil
	*idx = 0
}

func checkFlowUnpublish(ctx *zedrouterContext) {
	for k, m := range ctx.flowPublishMap {
		passed := int64(time.Since(m) / time.Second)
		if passed > flowStaleSec { // no update after 30 minutes, remove this flowlog
			log.Functionf("checkFlowUnpublish: key %s, sec passed %d, remove", k, passed)
			ctx.pubAppFlowMonitor.Unpublish(k)
			delete(ctx.flowPublishMap, k)
		}
	}
}

// DNSDhcpMonitor : DNS Query/Reply and DHCP monitor on bridges
func DNSDhcpMonitor(bn string, bnNum int, ctx *zedrouterContext, status *types.NetworkInstanceStatus) {
	var (
		err         error
		snapshotLen int32 = 1280             // draft-madi-dnsop-udp4dns-00
		promiscuous       = true             // mainly for switched network
		timeout           = 10 * time.Second // collect enough packets in 10sec before processing
		filter            = "udp and port 53"
		// raw instructions below are the compiled instructions of the filter above.
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
	if bnNum >= maxBridgeNumber {
		log.Errorf("Can not snoop on brige number %d", bnNum)
		return
	}
	if status.Type == types.NetworkInstanceTypeSwitch {
		switched = true
		filter = "(ip6 and icmp6 and ip6[40] == 135) or (udp and (port 53 or port 67 or port 546 or port 547))"
		// raw instructions below are the compiled instructions of the filter above.
		// tcpdump -dd "(ip6 and icmp6 and ip6[40] == 135) or (udp and (port 53 or port 67 or port 546 or port 547))"
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
	}
	log.Functionf("(FlowStats) DNS Monitor on %s(bridge-num %d) switched=%v, filter=%s", bn, bnNum, switched, filter)

	handle, err := pcap.OpenLive(bn, snapshotLen, promiscuous, timeout, false)
	if err != nil {
		log.Errorf("Can not snoop on bridge %s", bn)
		return
	}
	defer handle.Close()

	err = handle.SetRawBPFFilter(rawInstructions)
	if err != nil {
		log.Errorf("Can not install DNS filter [ %s ] on %s: %s", filter, bn, err)
		return
	}

	dnssys[bnNum].Done = make(chan bool)
	dnssys[bnNum].channelOpen = true
	packetSource := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
	dnsIn := packetSource.Packets()
	for {
		select {
		case <-dnssys[bnNum].Done:
			log.Noticef("(FlowStats) DNS Monitor exit on %s(bridge-num %d)", bn, bnNum)
			dnssys[bnNum].channelOpen = false
			dnssys[bnNum].Lock()
			dnsDataRemove(bnNum)
			dnssys[bnNum].Unlock()

			close(dnssys[bnNum].Done)
			return
		case packet, ok := <-dnsIn:
			if !ok {
				log.Noticef("(FlowStats) dnsIn closed on %s(bridge-num %d)", bn, bnNum)
				dnssys[bnNum].channelOpen = false
				dnssys[bnNum].Lock()
				dnsDataRemove(bnNum)
				dnssys[bnNum].Unlock()

				close(dnssys[bnNum].Done)
				return
			}
			dnslayer := packet.Layer(layers.LayerTypeDNS)
			if switched && dnslayer == nil {
				dnssys[bnNum].Lock()
				isDhcp := checkDHCPPacketInfo(bnNum, packet, ctx)
				if !isDhcp {
					checkDADProbe(ctx, bnNum, packet)
				}
				dnssys[bnNum].Unlock()
			} else {
				dnssys[bnNum].Lock()
				checkDNSPacketInfo(bnNum, packet, dnslayer)
				dnssys[bnNum].Unlock()
			}
		}
	}
}

// DNSStopMonitor : Stop DNS Query monitoring
func DNSStopMonitor(bnNum int) {
	log.Functionf("(FlowStats) Stop DNS Monitor on bridge-num %d", bnNum)
	if dnssys[bnNum].channelOpen {
		dnssys[bnNum].Done <- true
	}
}

func checkDADProbe(ctx *zedrouterContext, bnNum int, packet gopacket.Packet) {
	var foundSrcMac bool
	var vifInfo []types.VifNameMac
	var netstatus types.NetworkInstanceStatus
	var vifTrig types.VifIPTrig

	// use the IPAssigments of the NetworkInstanceStatus, since this is switched net
	// and the field will not be assigned or modified by others
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		netstatus = st.(types.NetworkInstanceStatus)
		if netstatus.Type != types.NetworkInstanceTypeSwitch || netstatus.BridgeNum != bnNum {
			continue
		}
		vifInfo = netstatus.Vifs
		break
	}
	if len(vifInfo) == 0 { // there is no Mac on the bridge
		log.Tracef("checkDADProbe: no mac on the bridge")
		return
	}

	var etherPkt *layers.Ethernet
	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		etherPkt, _ = etherLayer.(*layers.Ethernet)
		for _, vif := range vifInfo {
			if strings.Compare(etherPkt.SrcMAC.String(), vif.MacAddr) == 0 {
				foundSrcMac = true
				break
			}
		}
	}
	if !foundSrcMac {
		log.Tracef("checkDADProbe: pkt no dst mac for us\n")
		return
	}

	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		return
	}
	ip6 := ip6Layer.(*layers.IPv6)
	// We are looking for ICMPv6 Neighbor solicitation packet that
	// tries to find if the address calculated locally is a duplicate.
	// Such packets have a source IP of all zeroes (::)
	if ip6.SrcIP.String() != "::" {
		return
	}

	icmp6Layer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation)
	if icmp6Layer == nil {
		return
	}
	var vif *types.VifNameMac
	for index, v := range vifInfo {
		if strings.Compare(v.MacAddr, etherPkt.SrcMAC.String()) == 0 {
			vif = &vifInfo[index]
			break
		}
	}
	if vif == nil {
		return
	}

	icmp6, _ := icmp6Layer.(*layers.ICMPv6NeighborSolicitation)
	log.Tracef("ICMPv6: TargetAddress %s", icmp6.TargetAddress.String())

	if _, ok := netstatus.IPAssignments[vif.MacAddr]; !ok {
		log.Functionf("checkDADProbe: mac %v assign new IPv6 address %v\n",
			vif.MacAddr, icmp6.TargetAddress)
		addrs := types.AssignedAddrs{IPv6Addrs: []net.IP{icmp6.TargetAddress}}
		netstatus.IPAssignments[vif.MacAddr] = addrs
	} else {
		if !isAddrPresent(netstatus.IPAssignments[vif.MacAddr].IPv6Addrs, icmp6.TargetAddress) {
			log.Functionf("checkDADProbe: update mac list %v, new IPv6 %v\n",
				vif.MacAddr, icmp6.TargetAddress)
			addrs := netstatus.IPAssignments[vif.MacAddr]
			addrs.IPv6Addrs = append(addrs.IPv6Addrs, icmp6.TargetAddress)
			netstatus.IPAssignments[vif.MacAddr] = addrs
		} else {
			// No new addresses found and no updates required
			return
		}
	}
	ipv4Addr, snoopedIPv6s, _ := lookupVifIPTrig(ctx, vif.MacAddr)
	vifTrig.MacAddr = vif.MacAddr
	vifTrig.IPv4Addr = ipv4Addr
	if !isAddrPresent(snoopedIPv6s, icmp6.TargetAddress) {
		vifTrig.IPv6Addrs = append(snoopedIPv6s, icmp6.TargetAddress)
	} else {
		vifTrig.IPv6Addrs = snoopedIPv6s
	}

	log.Functionf("checkDADProbe: need update %v, %v\n", vifInfo, netstatus.IPAssignments)
	pub = ctx.pubNetworkInstanceStatus
	pub.Publish(netstatus.Key(), netstatus)
	ctx.pubAppVifIPTrig.Publish(vifTrig.MacAddr, vifTrig)
	checkAndPublishDhcpLeases(ctx)
}

func isAddrPresent(list []net.IP, addr net.IP) bool {
	for i := 0; i < len(list); i++ {
		if addr.Equal(list[i]) {
			return true
		}
	}
	return false
}

// Monitor the dhcp packets for switched network instance
// Returns true if the packet being inspected is DHCP or else returns false
func checkDHCPPacketInfo(bnNum int, packet gopacket.Packet, ctx *zedrouterContext) bool {
	var isReplyAck, foundDstMac, isBroadcast bool
	var vifInfo []types.VifNameMac
	var netstatus types.NetworkInstanceStatus
	var vifTrig types.VifIPTrig

	// use the IPAssigments of the NetworkInstanceStatus, since this is switched net
	// and the field will not be assigned or modified by others
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		netstatus = st.(types.NetworkInstanceStatus)
		if netstatus.Type != types.NetworkInstanceTypeSwitch || netstatus.BridgeNum != bnNum {
			continue
		}
		vifInfo = netstatus.Vifs
		break
	}
	if len(vifInfo) == 0 { // there is no Mac on the bridge
		log.Tracef("checkDHCPPacketInfo: no mac on the bridge")
		return false
	}

	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		etherPkt, _ := etherLayer.(*layers.Ethernet)
		if bytes.Compare(etherPkt.DstMAC, broadcastMAC) == 0 {
			// some DHCP servers send replies with broadcast MAC address,
			// need to check those in payload to see if it's for-us
			isBroadcast = true
		} else {
			for _, vif := range vifInfo {
				if strings.Compare(etherPkt.DstMAC.String(), vif.MacAddr) == 0 {
					foundDstMac = true
					break
				}
			}
		}
	}
	if !foundDstMac && !isBroadcast { // dhcp packet not for this bridge App ports
		log.Tracef("checkDHCPPacketInfo: pkt no dst mac for us\n")
		return false
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	isIPv4 := (ipLayer != nil)
	if isIPv4 {
		// dhcp client will send discovery or request, server will send offer and Ack
		// in the code we wait for the Reply from server with Ack to confirm the client's IP address
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			log.Tracef("checkDHCPPacketInfo: no dhcp layer")
			return false
		}
		dhcpv4, _ := dhcpLayer.(*layers.DHCPv4)
		if dhcpv4 != nil && dhcpv4.Operation == layers.DHCPOpReply {
			opts := dhcpv4.Options
			for _, opt := range opts {
				if opt.Type == layers.DHCPOptMessageType && int(opt.Data[0]) == int(layers.DHCPMsgTypeAck) {
					isReplyAck = true
					break
				}
			}
		}
		if !isReplyAck {
			return true
		}
		log.Tracef("checkDHCPPacketInfo: bn%d, Xid %d, clientip %s, yourclientip %s, clienthw %v, options %v\n",
			bnNum, dhcpv4.Xid, dhcpv4.ClientIP.String(), dhcpv4.YourClientIP.String(), dhcpv4.ClientHWAddr, dhcpv4.Options)

		var vif *types.VifNameMac
		for index, v := range vifInfo {
			if strings.Compare(v.MacAddr, dhcpv4.ClientHWAddr.String()) == 0 {
				vif = &vifInfo[index]
				break
			}
		}
		if vif == nil {
			return true
		}
		if _, ok := netstatus.IPAssignments[vif.MacAddr]; !ok {
			log.Functionf("checkDHCPPacketInfo: mac %v assign new IP %v\n", vif.MacAddr, dhcpv4.YourClientIP)
			addrs := types.AssignedAddrs{IPv4Addr: dhcpv4.YourClientIP}
			netstatus.IPAssignments[vif.MacAddr] = addrs
		} else {
			log.Functionf("checkDHCPPacketInfo: update mac %v, prev %v, now %v\n",
				vif.MacAddr, netstatus.IPAssignments[vif.MacAddr], dhcpv4.YourClientIP)
			addrs := netstatus.IPAssignments[vif.MacAddr]
			addrs.IPv4Addr = dhcpv4.YourClientIP
			netstatus.IPAssignments[vif.MacAddr] = addrs
		}
		log.Functionf("checkDHCPPacketInfo: need update %v, %v\n", vifInfo, netstatus.IPAssignments)
		_, snoopedIPv6s, _ := lookupVifIPTrig(ctx, vif.MacAddr)
		vifTrig.MacAddr = vif.MacAddr
		vifTrig.IPv4Addr = dhcpv4.YourClientIP
		vifTrig.IPv6Addrs = snoopedIPv6s

		pub := ctx.pubNetworkInstanceStatus
		pub.Publish(netstatus.Key(), netstatus)
		ctx.pubAppVifIPTrig.Publish(vifTrig.MacAddr, vifTrig)
		checkAndPublishDhcpLeases(ctx)
	} else {
		// XXX need to come back to handle ipv6 properly, including:
		// each MAC can have both ipv4 and ipv6 addresses
		// ipv6 can be stateful with DHCPv6 or stateless with autoconfig with RS/RA/etc
		// ipv6 can be link-local, global scope and rfc 4941 with many temporary addresses
		// which we don't know which one it will use and timeout
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
		if dhcpLayer == nil {
			return false
		}
		dhcpv6, _ := dhcpLayer.(*layers.DHCPv6)
		log.Tracef("DHCPv6: Msgtype %v, LinkAddr %s, PeerAddr %s, Options %v\n",
			dhcpv6.MsgType, dhcpv6.LinkAddr.String(), dhcpv6.PeerAddr.String(), dhcpv6.Options)

		//  We are only interested in DHCPv6 Reply packets. Skip others.
		if dhcpv6.MsgType != layers.DHCPv6MsgTypeReply {
			// This is indeed a DHCP packet but not the DHCP Reply type
			return true
		}
		for _, opt := range dhcpv6.Options {
			if opt.Code != layers.DHCPv6OptClientID {
				continue
			}
			clientOption := &layers.DHCPv6DUID{}
			clientOption.DecodeFromBytes(opt.Data)
			var vif *types.VifNameMac
			for index, v := range vifInfo {
				if strings.Compare(v.MacAddr, clientOption.LinkLayerAddress.String()) == 0 {
					vif = &vifInfo[index]
					break
				}
			}
			if vif == nil {
				return true
			}
			if _, ok := netstatus.IPAssignments[vif.MacAddr]; !ok {
				log.Functionf("checkDHCPPacketInfo: mac %v assign new IPv6 address %v\n", vif.MacAddr, dhcpv6.LinkAddr)
				addrs := types.AssignedAddrs{IPv6Addrs: []net.IP{dhcpv6.LinkAddr}}
				netstatus.IPAssignments[vif.MacAddr] = addrs
			} else {
				if !isAddrPresent(netstatus.IPAssignments[vif.MacAddr].IPv6Addrs, dhcpv6.LinkAddr) {
					log.Functionf("checkDHCPPacketInfo: update mac %v, prev IPv6 %v, new IPv6 %v\n",
						vif.MacAddr, netstatus.IPAssignments[vif.MacAddr], dhcpv6.LinkAddr)
					addrs := netstatus.IPAssignments[vif.MacAddr]
					addrs.IPv6Addrs = append(addrs.IPv6Addrs, dhcpv6.LinkAddr)
					netstatus.IPAssignments[vif.MacAddr] = addrs
				} else {
					// No new addresses found and hence no updates need to be done
					return true
				}
			}
			ipv4Addr, snoopedIPv6s, _ := lookupVifIPTrig(ctx, vif.MacAddr)
			vifTrig.MacAddr = vif.MacAddr
			vifTrig.IPv4Addr = ipv4Addr
			vifTrig.IPv6Addrs = append(snoopedIPv6s, dhcpv6.LinkAddr)

			pub := ctx.pubNetworkInstanceStatus
			pub.Publish(netstatus.Key(), netstatus)
			ctx.pubAppVifIPTrig.Publish(vifTrig.MacAddr, vifTrig)
			checkAndPublishDhcpLeases(ctx)
		}
	}
	return true
}

func checkDNSPacketInfo(bnNum int, packet gopacket.Packet, dnsLayer gopacket.Layer) {
	var DstIP net.IP
	var dnsentry dnsEntry
	if dnsLayer == nil {
		return
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		DstIP = ip.DstIP
		dnsentry.isIPv4 = true
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			DstIP = ipv6.DstIP
		}
	}

	dns, _ := dnsLayer.(*layers.DNS)
	if dns.ANCount <= 0 {
		return
	}
	dnsentry.AppIP = DstIP
	for _, dnsQ := range dns.Questions {
		var checkProto, haveAN bool
		dnsentry.DomainName = string(dnsQ.Name)
		dnsentry.TimeStamp = time.Now()
		dnsentry.ANCount = dns.ANCount
		for _, dnsA := range dns.Answers {
			if dnsA.Type != layers.DNSTypeA && dnsA.Type != layers.DNSTypeAAAA { // only for A or AAAA
				continue
			}
			if dnsA.IP.String() != "" {
				if checkProto == false {
					dnsentry.isIPv4 = dnsA.IP.To4() != nil
					checkProto = true
				}
				dnsentry.Answers = append(dnsentry.Answers, dnsA.IP)
				haveAN = true
			}
		}
		if haveAN {
			dnssys[bnNum].Snoop = append(dnssys[bnNum].Snoop, dnsentry)
			log.Tracef("!!--FlowStats: DNS collected for %s, bridge Number %d", string(dnsQ.Name), bnNum)
			break
		}
	}
}

func dnsDataRemove(bnNum int) {
	if len(dnssys[bnNum].Snoop) > 0 {
		dnssys[bnNum].Snoop = nil
	}
}

// brudgeStrToNum looks up the bridgeName to not depend on the names of
// the bridges
// XXX could the caller cache this?
func bridgeStrToNum(ctx *zedrouterContext, bnStr string) (int, error) {
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.NetworkInstanceStatus)
		if status.BridgeName == bnStr {
			return status.BridgeNum, nil
		}
	}
	return 0, fmt.Errorf("No NetworkInstanceStatus for bridgeName %s", bnStr)
}
