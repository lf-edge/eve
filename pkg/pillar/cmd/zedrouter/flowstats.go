// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Flow Statistics collection from IPtable Conntrack facility

package zedrouter

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eriknordmark/netlink"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/wrap"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"syscall"
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
	action    string
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
	maxBridgeNumber int    = 256
	timeoutSec      int32  = 150      // less than 150 sec, consider done
	markMask        uint32 = 0xffffff // get the Mark bits for ACL number
	appShiftBits    uint32 = 24       // top 8 bits for App Number
	maxFlowPack     int    = 280      // approximate 100 bytes per flow/dns, get this under 30k
)

type dnsSys struct {
	sync.Mutex
	Done        chan bool
	channelOpen bool
	Snoop       []dnsEntry
}

var loopcount int // XXX debug

var dnssys [maxBridgeNumber]dnsSys // per bridge DNS records for the collection period
var devUUID, nilUUID uuid.UUID

// FlowStatsCollect : Timer fired to collect iptable flow stats
func FlowStatsCollect(ctx *zedrouterContext) {
	var instData networkAttrs
	var timeOutTuples []flowStats
	var totalFlow int
	var dnsPacked bool

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

	if devUUID == nilUUID {
		b, err := ioutil.ReadFile("/config/uuid")
		if err != nil {
			log.Errorf("error in reading uuid\n")
			return
		}
		uuidStr := strings.TrimSpace(string(b))
		devUUID, err = uuid.FromString(uuidStr)
		if err != nil {
			log.Errorf("error in formating uuid\n")
			return
		}
	}

	checkAppAndACL(ctx, &instData)

	// Get IPv4/v6 conntrack table flows
	Protocols := [2]netlink.InetFamily{syscall.AF_INET, syscall.AF_INET6}
	for _, proto := range Protocols {
		connT, err := netlink.ConntrackTableList(netlink.ConntrackTable, proto)
		if err != nil {
			log.Errorf("FlowStats(%d): ContrackTableList", proto)
			return
		}

		log.Infof("***FlowStats(%d): device=%v, size of the flows %d\n", proto, devUUID, len(connT))

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

	log.Infof("FlowStats ++ Total timedout flows %d, loopcount debug %d\n", totalFlow, loopcount)
	loopcount++

	// per app/bridge packing flow stats to be uploaded
	for bnx := range instData.bnNet {
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
				DevID: devUUID,
				Scope: scope,
			}

			log.Infof("FlowStats: bnx=%s, appidx %d\n", bnx, appIdx)
			// temp print out the flow "tuple" and stats per app/bridge
			for i, tuple := range timeOutTuples { // search for flowstats by bridge
				var aclattr aclAttr
				var bridgeName, aclaction string
				var aclNum int

				appN := tuple.appNum
				if int(appN) != appIdx { // allow non-App flows to be uploaded
					//log.Infof("FlowStats: appN %d, appIdx %d not match", appN, appIdx)
					continue
				}

				if tuple.aclNum != DropMarkValue {
					tmpMap := instData.ipaclattr[int(appN)]
					if tmpMap != nil {
						if _, ok := tmpMap[int(tuple.aclNum)]; !ok {
							log.Infof("FlowStats: == can not get acl map with aclN, should not happen appN %d, aclN %d; %s\n",
								appN, tuple.aclNum, tuple.String())
							continue
						}
						aclattr = tmpMap[int(tuple.aclNum)]
					} else {
						log.Infof("FlowStats: == can't get acl map with appN, should not happen, appN %d, aclN %d; %s\n",
							appN, tuple.aclNum, tuple.String())
						continue
					}
					if aclattr.aclNum == 0 {
						log.Infof("FlowStats: == aclN zero in attr, appN %d, aclN %d; %s\n", appN, tuple.aclNum, tuple.String())
						// some debug info
						continue
					}

					bridgeName = aclattr.bridge
					if strings.Compare(bnx, bridgeName) != 0 {
						log.Infof("FlowStats: == bridge name not match %s, %s\n", bnx, bridgeName)
						continue
					}
					scope.Intf = aclattr.intfname // App side DomU internal interface name
					aclaction = aclattr.action
					aclNum = int(aclattr.aclNum)
				} else { // conntrack mark aclNum field being 0xffffff
					// special drop aclNum
					appinfo := flowGetAppInfo(tuple, instData.appIPinfo[appIdx])
					if appinfo.localintf != bnx {
						continue
					}
					scope.Intf = appinfo.intf
					bridgeName = appinfo.localintf
					aclaction = "drop-" + bridgeName + "-" + appinfo.intf
					aclNum = 0
				}

				bnNum, err := bridgeStrToNum(bridgeName)
				if err != nil {
					continue
				}
				// temp print out log for the flow
				log.Infof("FlowStats [%d]: on bn%d %s\n", i, bnNum, tuple.String()) // just print for now

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

			if len(flowdata.Flows) == 0 { // this app/brigde does not match any timedout flow
				continue
			}

			var dnsrec [2]map[string]dnsEntry
			dnsrec[0] = make(map[string]dnsEntry) // store IPv4 addresses from dns
			dnsrec[1] = make(map[string]dnsEntry) // store IPv6 addresses from dns
			bnNum, err := bridgeStrToNum(bnx)
			if err != nil {
				continue
			}

			// get the bringe-X dns request/replies
			dnssys[bnNum].Lock()
			defer dnssys[bnNum].Unlock()
			for _, dnsdata := range dnssys[bnNum].Snoop {
				// unique by domain name, latest reply overwrite previous ones
				if dnsdata.isIPv4 {
					dnsrec[0][dnsdata.DomainName] = dnsdata
				} else {
					dnsrec[1][dnsdata.DomainName] = dnsdata
				}
			}
			for idx := range dnsrec {
				for _, dnsRec := range dnsrec[idx] {
					// temp print out all unique dns replies for the bridge
					log.Infof("!!FlowStats: DNS time %v, domain %s, appIP %v, count %d, Answers %v",
						dnsRec.TimeStamp, dnsRec.DomainName, dnsRec.AppIP, dnsRec.ANCount, dnsRec.Answers)

					dnsrec := types.DNSReq{
						HostName:    dnsRec.DomainName,
						Addrs:       dnsRec.Answers,
						RequestTime: dnsRec.TimeStamp.UnixNano(),
					}
					dnsPacked = true
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

	// remove the dns data already uploaded
	if dnsPacked {
		for bnx := range instData.bnNet {
			bnNum, err := bridgeStrToNum(bnx)
			if err != nil {
				continue
			}
			dnssys[bnNum].Snoop = nil
			log.Infof("!!FlowStats: clear dns record for bn%d", bnNum)
		}
	}
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

	ipFlow.aclNum = entry.Mark & markMask
	ipFlow.appNum = uint8(entry.Mark >> appShiftBits)
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
	// If the App initiated the traffic, then the forw.src is the App IP, or the reverse.dst
	// is the App IP
	if forwSrcApp {
		ipFlow.dbg2 = 1
		ipFlow.SrcIP = entry.Forward.SrcIP
		ipFlow.DstIP = entry.Reverse.SrcIP
		ipFlow.SrcPort = entry.Forward.SrcPort
		ipFlow.DstPort = entry.Reverse.DstPort
		ipFlow.AppInitiate = true
	} else if forwDstApp {
		ipFlow.dbg2 = 2
		ipFlow.DstIP = entry.Forward.DstIP
		ipFlow.SrcIP = entry.Reverse.DstIP
		ipFlow.DstPort = entry.Forward.DstPort
		ipFlow.SrcPort = entry.Reverse.DstPort
	} else if backSrcApp {
		ipFlow.dbg2 = 3
		ipFlow.SrcIP = entry.Forward.SrcIP
		ipFlow.DstIP = entry.Reverse.SrcIP
		ipFlow.SrcPort = entry.Forward.SrcPort
		ipFlow.DstPort = entry.Reverse.SrcPort
	} else if backDstApp {
		ipFlow.dbg2 = 4
		ipFlow.SrcIP = entry.Reverse.DstIP
		ipFlow.DstIP = entry.Forward.DstIP
		ipFlow.SrcPort = entry.Reverse.DstPort
		ipFlow.DstPort = entry.Forward.DstPort
		ipFlow.AppInitiate = true
	} else { // if we can not find our App endpoint is part of the flow, something is wrong
		ipFlow.dbg2 = 5
		log.Infof("FlowStats: flow entry can not locate app IP address, appNum %d, %s", AppNum, entry.String())
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
		status := cast.CastAppNetworkStatus(st)
		for i, ulStatus := range status.UnderlayNetworkList {
			log.Infof("===FlowStats: (index %d) AppNum %d, VifInfo %v, IP addr %v, Hostname %s\n",
				i, status.AppNum, ulStatus.VifInfo, ulStatus.AllocatedIPAddr, ulStatus.HostName)

			// build an App-IPaddress/intfs cache indexed by App-number
			if ulStatus.AllocatedIPAddr != "" {
				tmpAppInfo := appInfo{
					ipaddr:    net.ParseIP(ulStatus.AllocatedIPAddr),
					intf:      ulStatus.Name,
					localintf: ulStatus.Bridge,
				}
				instData.appIPinfo[status.AppNum] = append(instData.appIPinfo[status.AppNum], tmpAppInfo)
			}

			// Fill in the bnNet indexed by bridge-name, used for loop through bridges, and Scope
			ulconfig := ulStatus.UnderlayNetworkConfig
			intfAttr := bridgeAttr{
				bridge:  ulStatus.Bridge,
				netUUID: ulconfig.Network,
			}
			instData.bnNet[ulStatus.Bridge] = intfAttr

			// build an App list cache, used for loop through all the Apps
			if instData.appNet[status.AppNum] == nilUUID {
				instData.appNet[status.AppNum] = status.UUIDandVersion.UUID
				log.Infof("===FlowStats: appNet appNum %d, uuid %v\n", status.AppNum, instData.appNet[status.AppNum])
			}

			// build an acl cache indexed by app/aclnum, from flow MARK, we can get this aclAttr info
			tmpMap := instData.ipaclattr[status.AppNum]
			if tmpMap == nil {
				tmpMap := make(map[int]aclAttr)
				instData.ipaclattr[status.AppNum] = tmpMap
			}
			for _, rule := range ulStatus.ACLRules {
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
				if len(rule.Action) >= 2 { // '-j ACCEPT', '-j drop-all-bn1-nbu2x1'
					tempAttr.action = rule.Action[1]
				}
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
	ctx.pubAppFlowMonitor.Publish(flowKey, flowdata)
	log.Infof("FlowStats: publish to zedagent: total records %d, sequence %d\n", *idx, *seq)
	*seq++
	flowdata.Flows = nil
	flowdata.DNSReqs = nil
	*idx = 0
}

// DNSMonitor : DNS Query and Reply monitor on bridges
func DNSMonitor(bn string, bnNum int, ctx *zedrouterContext, status *types.NetworkInstanceStatus) {
	var (
		err error
		//action      string
		snapshotLen int32 = 1280             // draft-madi-dnsop-udp4dns-00
		promiscuous       = true             // mainly for switched network
		timeout           = 10 * time.Second // collect enough packets in 10sec before processing
		handle      *pcap.Handle
		filter      = "udp and port 53"
		switched    bool
		// XXX come back to handle TCP DNS snoop, more useful for zone transfer
		// https://github.com/google/gopacket/issues/236
	)
	if bnNum >= maxBridgeNumber {
		log.Errorf("Can not snoop on brige number %d", bnNum)
		return
	}
	if status.Type == types.NetworkInstanceTypeSwitch {
		switched = true
		filter = "udp and (port 53 or port 67)"
	}
	log.Infof("(FlowStats) DNS Monitor on %s(bridge-num %d) swithced=%v, filter=%s", bn, bnNum, switched, filter)

	handle, err = pcap.OpenLive(bn, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Errorf("Can not snoop on bridge %s", bn)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Errorf("Can not install DNS filter on %s", bn)
		return
	}

	dnssys[bnNum].Done = make(chan bool)
	dnssys[bnNum].channelOpen = true
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	dnsIn := packetSource.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-dnssys[bnNum].Done:
			log.Infof("(FlowStats) DNS Monitor exit on %s(bridge-num %d)", bn, bnNum)
			dnssys[bnNum].channelOpen = false
			dnssys[bnNum].Lock()
			dnsDataRemove(bnNum)
			dnssys[bnNum].Unlock()

			close(dnssys[bnNum].Done)
			return
		case packet = <-dnsIn:
			dnslayer := packet.Layer(layers.LayerTypeDNS)
			if switched && dnslayer == nil {
				checkDHCPPacketInfo(bnNum, packet, ctx)
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
	log.Infof("(FlowStats) Stop DNS Monitor on bridge-num %d", bnNum)
	if dnssys[bnNum].channelOpen {
		dnssys[bnNum].Done <- true
	}
}

// Monitor the dhcp packets for switched network instance
func checkDHCPPacketInfo(bnNum int, packet gopacket.Packet, ctx *zedrouterContext) {
	var isIPv4, isReplyAck, needUpdate, foundDstMac bool
	var vifInfo []types.VifNameMac
	var netstatus types.NetworkInstanceStatus

	// use the IPAssigments of the NetworkInstanceStatus, since this is switched net
	// and the field will not be assigned or modified by others
	pub := ctx.pubNetworkInstanceStatus
	items := pub.GetAll()
	for _, st := range items {
		netstatus = cast.CastNetworkInstanceStatus(st)
		if netstatus.Type != types.NetworkInstanceTypeSwitch || netstatus.BridgeNum != bnNum {
			continue
		}
		vifInfo = netstatus.Vifs
		break
	}
	if len(vifInfo) == 0 { // there is no Mac on the bridge
		return
	}

	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		etherPkt, _ := etherLayer.(*layers.Ethernet)
		for _, vif := range vifInfo {
			if strings.Compare(etherPkt.DstMAC.String(), vif.MacAddr) == 0 {
				foundDstMac = true
				break
			}
		}
	}
	if foundDstMac == false { // dhcp packet not for this bridge App ports
		log.Infof("checkDHCPPacketInfo: pkt no dst mac for us\n")
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		isIPv4 = true
	}
	if isIPv4 {
		// dhcp client will send discovery or request, server will send offer and Ack
		// in the code we wait for the Reply from server with Ack to confirm the client's IP address
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer != nil {
			dhcpv4, _ := dhcpLayer.(*layers.DHCPv4)
			if dhcpv4.Operation == layers.DHCPOpReply {
				opts := dhcpv4.Options
				for _, opt := range opts {
					if opt.Type == layers.DHCPOptMessageType && int(opt.Data[0]) == int(layers.DHCPMsgTypeAck) {
						isReplyAck = true
						break
					}
				}
			}
			if isReplyAck {
				log.Infof("checkDHCPPacketInfo: bn%d, Xid %d, clientip %s, yourclientip %s, clienthw %v, options %v\n",
					bnNum, dhcpv4.Xid, dhcpv4.ClientIP.String(), dhcpv4.YourClientIP.String(), dhcpv4.ClientHWAddr, dhcpv4.Options)
				for _, vif := range vifInfo {
					if strings.Compare(vif.MacAddr, dhcpv4.ClientHWAddr.String()) == 0 {
						if _, ok := netstatus.IPAssignments[vif.MacAddr]; !ok {
							log.Infof("checkDHCPPacketInfo: mac %v assign new IP %v\n", vif.MacAddr, dhcpv4.YourClientIP)
							netstatus.IPAssignments[vif.MacAddr] = dhcpv4.YourClientIP
							needUpdate = true
						} else {
							if netstatus.IPAssignments[vif.MacAddr].Equal(dhcpv4.YourClientIP) == false {
								log.Infof("checkDHCPPacketInfo: update mac %v, prev %v, now %v\n",
									vif.MacAddr, netstatus.IPAssignments[vif.MacAddr], dhcpv4.YourClientIP)
								netstatus.IPAssignments[vif.MacAddr] = dhcpv4.YourClientIP
								needUpdate = true
							}
						}
						break
					}
				}
			}
		} else {
			log.Infof("checkDHCPPacketInfo: no dhcp layer\n")
		}
	} else {
		// XXX need to come back to handle ipv6 properly, including:
		// each MAC can have both ipv4 and ipv6 addresses
		// ipv6 can be stateful with DHCPv6 or stateless with autoconfig with RS/RA/etc
		// ipv6 can be link-local, global scope and rfc 4941 with many temporary addresses
		// which we don't know which one it will use and timeout
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv6)
		if dhcpLayer != nil {
			dhcpv6, _ := dhcpLayer.(*layers.DHCPv6)
			log.Infof("DHCPv6: Msgtype %v, LinkAddr %s, PeerAddr %s, Options %v\n",
				dhcpv6.MsgType, dhcpv6.LinkAddr.String(), dhcpv6.PeerAddr.String(), dhcpv6.Options)
		}
	}

	if needUpdate {
		log.Infof("checkDHCPPacketInfo: need update %v, %v\n", vifInfo, netstatus.IPAssignments)
		publishNetworkInstanceStatus(ctx, &netstatus)
	}
}

func checkDNSPacketInfo(bnNum int, packet gopacket.Packet, dnsLayer gopacket.Layer) {
	var DstIP net.IP
	var dnsentry dnsEntry
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

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if dns.ANCount > 0 {
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
					log.Infof("!!--FlowStats: DNS collected for %s, bridge Number %d", string(dnsQ.Name), bnNum)
					break
				}
			}
		}
	}
}

func dnsDataRemove(bnNum int) {
	if len(dnssys[bnNum].Snoop) > 0 {
		dnssys[bnNum].Snoop = nil
	}
}

func bridgeStrToNum(bnStr string) (int, error) {
	bnNumStr := strings.TrimPrefix(bnStr, "bn")
	if len(bnNumStr) == len(bnStr) {
		err := fmt.Errorf("bridge name:%s incorrect", bnStr)
		return 0, err
	}
	bnNum, err := strconv.Atoi(bnNumStr)
	if err != nil {
		return 0, err
	}
	return bnNum, nil
}

func flowTimeOutSet(item string, origValue int) {

	tOutValue := origValue + int(timeoutSec) // add 150 seconds
	setStr := item + "=" + strconv.Itoa(tOutValue)
	_, err := wrap.Command("sysctl", "-w", setStr).Output()
	if err != nil {
		log.Errorf("FlowStats: set item %s error", setStr)
	}
}

// AppFlowMonitorTimeoutAdjust :
// Adjust the conntrack flow session timeout values
// by adding 150 seconds on top of default seconds
func AppFlowMonitorTimeoutAdjust() {

	baseStr := "net.netfilter.nf_conntrack_"

	flowTimeOutSet(baseStr+"tcp_timeout_fin_wait", 120)

	flowTimeOutSet(baseStr+"tcp_timeout_last_ack", 30)

	flowTimeOutSet(baseStr+"tcp_timeout_max_retrans", 300)

	flowTimeOutSet(baseStr+"tcp_timeout_syn_recv", 60)

	flowTimeOutSet(baseStr+"tcp_timeout_syn_sent", 120)

	flowTimeOutSet(baseStr+"tcp_timeout_time_wait", 120)

	flowTimeOutSet(baseStr+"tcp_timeout_unacknowledged", 300)

	flowTimeOutSet(baseStr+"udp_timeout", 30)

	flowTimeOutSet(baseStr+"udp_timeout_stream", 180)

	flowTimeOutSet(baseStr+"dccp_timeout_closereq", 64)

	flowTimeOutSet(baseStr+"dccp_timeout_closing", 64)

	// default was 432000 (5 days) see discussion https://dev.archive.openwrt.org/ticket/12976.html
	flowTimeOutSet(baseStr+"dccp_timeout_open", 3600)

	flowTimeOutSet(baseStr+"dccp_timeout_partopen", 480)

	flowTimeOutSet(baseStr+"dccp_timeout_request", 240)

	flowTimeOutSet(baseStr+"dccp_timeout_respond", 480)

	flowTimeOutSet(baseStr+"dccp_timeout_timewait", 240)

	flowTimeOutSet(baseStr+"frag6_timeout", 60)

	flowTimeOutSet(baseStr+"generic_timeout", 600)

	flowTimeOutSet(baseStr+"icmp_timeout", 30)

	flowTimeOutSet(baseStr+"icmpv6_timeout", 30)

	flowTimeOutSet(baseStr+"sctp_timeout_closed", 10)

	flowTimeOutSet(baseStr+"sctp_timeout_cookie_echoed", 3)

	flowTimeOutSet(baseStr+"sctp_timeout_cookie_wait", 3)

	flowTimeOutSet(baseStr+"sctp_timeout_established", 3600)

	flowTimeOutSet(baseStr+"sctp_timeout_heartbeat_acked", 210)

	flowTimeOutSet(baseStr+"sctp_timeout_heartbeat_sent", 30)

	flowTimeOutSet(baseStr+"sctp_timeout_shutdown_ack_sent", 3)

	flowTimeOutSet(baseStr+"sctp_timeout_shutdown_recd", 0)

	flowTimeOutSet(baseStr+"sctp_timeout_shutdown_sent", 0)

	flowTimeOutSet(baseStr+"tcp_timeout_close", 10)

	flowTimeOutSet(baseStr+"tcp_timeout_close_wait", 60)

	flowTimeOutSet(baseStr+"tcp_timeout_established", 3600)
}
