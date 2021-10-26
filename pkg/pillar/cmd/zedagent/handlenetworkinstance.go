// Copyright (c) 2018,2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkInstanceStatus from zedrouter

package zedagent

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/api/go/flowlog"
	zinfo "github.com/lf-edge/eve/api/go/info"   // XXX need to stop using
	zmet "github.com/lf-edge/eve/api/go/metrics" // zinfo and zmet here
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

func handleNetworkInstanceCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleNetworkInstanceImpl(ctxArg, key, statusArg)
}

func handleNetworkInstanceModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleNetworkInstanceImpl(ctxArg, key, statusArg)
}

func handleNetworkInstanceImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNetworkInstanceStatusImpl(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.NetworkInstanceStatus)
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkInstance error %s",
			status.Error)
	}
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, false)
	log.Functionf("handleNetworkInstanceImpl(%s) done", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleNetworkInstanceDelete(%s)", key)
	status := statusArg.(types.NetworkInstanceStatus)
	ctx := ctxArg.(*zedagentContext)
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, true)
	log.Functionf("handleNetworkInstanceDelete(%s) done", key)
}

// prepareAndPublishNetworkInstanceInfoMsg sends a message
// which is mostly empty if deleted is set as a delete indication.
// XXX When a network instance is deleted it is ideal to
// send a flag such as deleted/gone inside
// ZInfoNetworkInstance message. Having a separate flag
// (indicating deletion) would make is explicit
// and easy for the cloud process.
func prepareAndPublishNetworkInstanceInfoMsg(ctx *zedagentContext,
	status types.NetworkInstanceStatus, deleted bool) {

	infoMsg := &zinfo.ZInfoMsg{}
	infoType := new(zinfo.ZInfoTypes)
	*infoType = zinfo.ZInfoTypes_ZiNetworkInstance
	infoMsg.DevId = *proto.String(devUUID.String())
	infoMsg.Ztype = *infoType
	infoMsg.AtTimeStamp = ptypes.TimestampNow()

	uuid := status.Key()
	info := new(zinfo.ZInfoNetworkInstance)
	info.NetworkID = uuid
	info.NetworkVersion = status.UUIDandVersion.Version
	if !deleted {
		info.Displayname = status.DisplayName
		info.InstType = uint32(status.Type)
		info.CurrentUplinkIntf = status.CurrentUplinkIntf

		if !status.ErrorTime.IsZero() {
			errInfo := new(zinfo.ErrorInfo)
			errInfo.Description = status.Error
			errTime, _ := ptypes.TimestampProto(status.ErrorTime)
			errInfo.Timestamp = errTime
			info.NetworkErr = append(info.NetworkErr, errInfo)
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_ERROR
		} else if status.Activated {
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		} else {
			info.State = zinfo.ZNetworkInstanceState_ZNETINST_STATE_INIT
		}
		info.Activated = status.Activated

		info.BridgeNum = uint32(status.BridgeNum)
		info.BridgeName = status.BridgeName
		info.BridgeIPAddr = status.BridgeIPAddr

		for mac, addrs := range status.IPAssignments {
			assignment := new(zinfo.ZmetIPAssignmentEntry)
			assignment.MacAddress = mac
			if !addrs.IPv4Addr.Equal(net.IP{}) {
				assignment.IpAddress = append(assignment.IpAddress, addrs.IPv4Addr.String())
			}
			for _, ip := range addrs.IPv6Addrs {
				assignment.IpAddress = append(assignment.IpAddress, ip.String())
			}
			info.IpAssignments = append(info.IpAssignments, assignment)
		}
		for _, s := range status.BridgeIPSets {
			info.BridgeIPSets = append(info.BridgeIPSets, s)
		}
		for _, v := range status.Vifs {
			vi := new(zinfo.ZmetVifInfo)
			vi.VifName = v.Name
			vi.MacAddress = v.MacAddr
			vi.AppID = v.AppID.String()
			info.Vifs = append(info.Vifs, vi)
		}
		for _, ifname := range status.IfNameList {
			ia := ctx.assignableAdapters.LookupIoBundleIfName(ifname)
			if ia == nil {
				log.Warnf("Missing adapter for ifname %s", ifname)
				continue
			}
			reportAA := new(zinfo.ZioBundle)
			reportAA.Type = zcommon.PhyIoType(ia.Type)
			reportAA.Name = ia.Logicallabel
			// XXX Add Phylabel in protobuf message?
			reportAA.UsedByAppUUID = devUUID.String()
			list := ctx.assignableAdapters.LookupIoBundleAny(ia.Phylabel)
			for _, ib := range list {
				if ib == nil {
					continue
				}
				reportAA.Members = append(reportAA.Members, ib.Logicallabel)
				if ib.MacAddr != "" {
					reportMac := new(zinfo.IoAddresses)
					reportMac.MacAddress = ib.MacAddr
					reportAA.IoAddressList = append(reportAA.IoAddressList,
						reportMac)
				}
				log.Tracef("AssignableAdapters for %s macs %v",
					reportAA.Name, reportAA.IoAddressList)
			}
			info.AssignedAdapters = append(info.AssignedAdapters,
				reportAA)
		}

		// fill Vpn info
		if status.VpnStatus != nil {
			fillVpnInfo(info, status.VpnStatus)
		}
	}

	infoMsg.InfoContent = new(zinfo.ZInfoMsg_Niinfo)
	if x, ok := infoMsg.GetInfoContent().(*zinfo.ZInfoMsg_Niinfo); ok {
		x.Niinfo = info
	}
	log.Tracef("Publish NetworkInstance Info message to zedcloud: %v",
		infoMsg)

	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("Publish NetworkInstance proto marshaling error: ", err)
	}
	statusURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(infoMsg))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	zedcloud.SetDeferred(zedcloudCtx, uuid, buf, size, statusURL,
		true, zinfo.ZInfoTypes_ZiNetworkInstance)
	zedcloud.HandleDeferred(zedcloudCtx, time.Now(), 0, true)
}

func fillVpnInfo(info *zinfo.ZInfoNetworkInstance, vpnStatus *types.VpnStatus) {

	info.SoftwareList = new(zinfo.ZInfoSW)
	info.SoftwareList.SwVersion = vpnStatus.Version
	upTime, _ := ptypes.TimestampProto(vpnStatus.UpTime)
	info.UpTimeStamp = upTime

	vpnInfo := new(zinfo.ZInfoVpn)
	vpnInfo.PolicyBased = vpnStatus.PolicyBased
	listeningIpAddrs := strings.Split(vpnStatus.IpAddrs, " ")
	vpnInfo.ListeningIpAddrs = make([]string, len(listeningIpAddrs))
	for idx, ipAddr := range listeningIpAddrs {
		vpnInfo.ListeningIpAddrs[idx] = ipAddr
	}

	totalConnCount := len(vpnStatus.StaleVpnConns) + len(vpnStatus.ActiveVpnConns)

	if totalConnCount == 0 {
		info.InfoContent = new(zinfo.ZInfoNetworkInstance_Vinfo)
		if x, ok := info.GetInfoContent().(*zinfo.ZInfoNetworkInstance_Vinfo); ok {
			x.Vinfo = vpnInfo
		}
		return
	}

	vpnInfo.Conn = make([]*zinfo.ZInfoVpnConn, totalConnCount)
	// stale connections
	connIdx := 0
	for _, vpnConn := range vpnStatus.StaleVpnConns {
		vpnConnInfo := publishVpnConnection(vpnInfo, vpnConn)
		if vpnConnInfo != nil {
			vpnInfo.Conn[connIdx] = vpnConnInfo
			connIdx++
		}
	}

	// active connections
	for _, vpnConn := range vpnStatus.ActiveVpnConns {
		vpnConnInfo := publishVpnConnection(vpnInfo, vpnConn)
		if vpnConnInfo != nil {
			vpnInfo.Conn[connIdx] = vpnConnInfo
			connIdx++
		}
	}

	info.InfoContent = new(zinfo.ZInfoNetworkInstance_Vinfo)
	if x, ok := info.GetInfoContent().(*zinfo.ZInfoNetworkInstance_Vinfo); ok {
		x.Vinfo = vpnInfo
	}
}

func protoEncodeGenericInstanceMetric(status types.NetworkInstanceMetrics,
	metric *zmet.ZMetricNetworkInstance) {
	networkStats := new(zmet.ZMetricNetworkStats)
	rxStats := new(zmet.NetworkStats)
	txStats := new(zmet.NetworkStats)
	netMetric := status.NetworkMetrics.MetricList[0]
	rxStats.TotalPackets = netMetric.RxPkts
	rxStats.TotalBytes = netMetric.RxBytes
	rxStats.Errors = netMetric.RxErrors
	// Add all types of Rx drops
	var drops uint64 = 0
	drops += netMetric.RxDrops
	drops += netMetric.RxAclDrops
	drops += netMetric.RxAclRateLimitDrops
	rxStats.Drops = drops

	txStats.TotalPackets = netMetric.TxPkts
	txStats.TotalBytes = netMetric.TxBytes
	txStats.Errors = netMetric.TxErrors
	// Add all types of Tx drops
	drops = 0
	drops += netMetric.TxDrops
	drops += netMetric.TxAclDrops
	drops += netMetric.TxAclRateLimitDrops
	txStats.Drops = drops

	networkStats.Rx = rxStats
	networkStats.Tx = txStats
	metric.NetworkStats = networkStats
}

func protoEncodeVpnInstanceMetric(metrics types.NetworkInstanceMetrics,
	instanceMetrics *zmet.ZMetricNetworkInstance) {

	if metrics.VpnMetrics == nil {
		return
	}
	protoEncodeGenericInstanceMetric(metrics, instanceMetrics)

	stats := metrics.VpnMetrics
	vpnMetric := new(zmet.ZMetricVpn)
	vpnMetric.ConnStat = protoEncodeVpnInstanceStat(stats.DataStat)
	vpnMetric.NatTStat = protoEncodeVpnInstanceStat(stats.NatTStat)
	vpnMetric.IkeStat = protoEncodeVpnInstanceStat(stats.IkeStat)
	vpnMetric.EspStat = protoEncodeVpnInstanceStat(stats.EspStat)

	instanceMetrics.InstanceContent = new(zmet.ZMetricNetworkInstance_Vpnm)
	if x, ok := instanceMetrics.GetInstanceContent().(*zmet.ZMetricNetworkInstance_Vpnm); ok {
		x.Vpnm = vpnMetric
	}
	protoEncodeVpnInstanceFlowMetric(metrics, instanceMetrics)
}

func protoEncodeVpnInstanceStat(stats types.LinkPktStats) *zmet.ZMetricConn {
	connStat := new(zmet.ZMetricConn)
	connStat.InPkts = new(zmet.PktStat)
	connStat.OutPkts = new(zmet.PktStat)
	connStat.InPkts.Packets = stats.InPkts.Pkts
	connStat.InPkts.Bytes = stats.InPkts.Bytes
	connStat.OutPkts.Packets = stats.OutPkts.Pkts
	connStat.OutPkts.Bytes = stats.OutPkts.Bytes
	return connStat
}

func protoEncodeVpnInstanceFlowMetric(metrics types.NetworkInstanceMetrics,
	instanceMetrics *zmet.ZMetricNetworkInstance) {

	if len(metrics.VpnMetrics.VpnConns) == 0 {
		return
	}

	vpnMetrics := metrics.VpnMetrics
	instanceMetrics.FlowStats = make([]*zmet.ZMetricFlow,
		len(vpnMetrics.VpnConns))
	for idx, connStats := range vpnMetrics.VpnConns {

		flowStats := new(zmet.ZMetricFlow)
		flowStats.Id = connStats.Id
		flowStats.Name = connStats.Name
		flowStats.Type = uint32(connStats.Type)
		flowStats.EstTime = connStats.EstTime

		lEndPoint := protoEncodeVpnMetricEndPtIpAddr(connStats.LEndPoint)
		lEndPoint.Stats = protoEncodeVpnMetricStats(connStats.LEndPoint.PktStats)
		lLink := protoEncodeVpnMetricLink(connStats.LEndPoint.LinkInfo)
		lEndPoint.Link = make([]*zmet.ZMetricFlowLink, 1)
		lEndPoint.Link[0] = lLink

		rEndPoint := protoEncodeVpnMetricEndPtIpAddr(connStats.REndPoint)
		rEndPoint.Stats = protoEncodeVpnMetricStats(connStats.REndPoint.PktStats)
		rLink := protoEncodeVpnMetricLink(connStats.REndPoint.LinkInfo)
		rEndPoint.Link = make([]*zmet.ZMetricFlowLink, 1)
		rEndPoint.Link[0] = rLink

		flowStats.LEndPoint = lEndPoint
		flowStats.REndPoint = make([]*zmet.ZMetricFlowEndPoint, 1)
		flowStats.REndPoint[0] = rEndPoint
		instanceMetrics.FlowStats[idx] = flowStats
	}
}

func protoEncodeVpnMetricEndPtIpAddr(endPInfo types.VpnEndPointMetrics) *zmet.ZMetricFlowEndPoint {
	endPoint := new(zmet.ZMetricFlowEndPoint)
	endPoint.Endpoint = new(zmet.ZMetricFlowEndPoint_IpAddr)
	if x, ok := endPoint.GetEndpoint().(*zmet.ZMetricFlowEndPoint_IpAddr); ok {
		x.IpAddr = endPInfo.IpAddr
	}
	return endPoint
}

func protoEncodeVpnMetricLink(linkInfo types.VpnLinkMetrics) *zmet.ZMetricFlowLink {
	link := new(zmet.ZMetricFlowLink)
	link.SpiId = linkInfo.SpiId
	link.Link = new(zmet.ZMetricFlowLink_SubNet)
	if x, ok := link.GetLink().(*zmet.ZMetricFlowLink_SubNet); ok {
		x.SubNet = linkInfo.SubNet
	}
	return link
}

func protoEncodeVpnMetricStats(linkStats types.PktStats) *zmet.PktStat {
	pktStats := new(zmet.PktStat)
	pktStats.Bytes = linkStats.Bytes
	pktStats.Packets = linkStats.Pkts
	return pktStats
}

func publishVpnConnection(vpnInfo *zinfo.ZInfoVpn,
	vpnConn *types.VpnConnStatus) *zinfo.ZInfoVpnConn {
	if vpnConn == nil {
		return nil
	}
	vpnConnInfo := new(zinfo.ZInfoVpnConn)
	vpnConnInfo.Id = vpnConn.Id
	vpnConnInfo.Name = vpnConn.Name
	vpnConnInfo.State = zinfo.ZInfoVpnState(vpnConn.State)
	vpnConnInfo.Ikes = vpnConn.Ikes
	vpnConnInfo.EstTime = vpnConn.EstTime
	vpnConnInfo.Version = vpnConn.Version

	lEndPointInfo := new(zinfo.ZInfoVpnEndPoint)
	lEndPointInfo.Id = vpnConn.LInfo.Id
	lEndPointInfo.IpAddr = vpnConn.LInfo.IpAddr
	lEndPointInfo.Port = vpnConn.LInfo.Port
	vpnConnInfo.LInfo = lEndPointInfo

	rEndPointInfo := new(zinfo.ZInfoVpnEndPoint)
	rEndPointInfo.Id = vpnConn.RInfo.Id
	rEndPointInfo.IpAddr = vpnConn.RInfo.IpAddr
	rEndPointInfo.Port = vpnConn.RInfo.Port
	vpnConnInfo.RInfo = rEndPointInfo

	if len(vpnConn.Links) == 0 {
		return vpnConnInfo
	}
	vpnConnInfo.Links = make([]*zinfo.ZInfoVpnLink, len(vpnConn.Links))

	for idx, linkData := range vpnConn.Links {
		linkInfo := new(zinfo.ZInfoVpnLink)
		linkInfo.Id = linkData.Id
		linkInfo.ReqId = linkData.ReqId
		linkInfo.InstTime = linkData.InstTime
		linkInfo.EspInfo = linkData.EspInfo
		linkInfo.State = zinfo.ZInfoVpnState(linkData.State)

		linfo := new(zinfo.ZInfoVpnLinkInfo)
		linfo.SubNet = linkData.LInfo.SubNet
		linfo.SpiId = linkData.LInfo.SpiId
		linfo.Direction = linkData.LInfo.Direction
		linkInfo.LInfo = linfo

		rinfo := new(zinfo.ZInfoVpnLinkInfo)
		rinfo.SubNet = linkData.RInfo.SubNet
		rinfo.SpiId = linkData.RInfo.SpiId
		rinfo.Direction = linkData.RInfo.Direction
		linkInfo.RInfo = rinfo

		vpnConnInfo.Links[idx] = linkInfo
	}

	return vpnConnInfo
}

func handleAppFlowMonitorCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppFlowMonitorImpl(ctxArg, key, statusArg)
}

func handleAppFlowMonitorModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppFlowMonitorImpl(ctxArg, key, statusArg)
}

func handleAppFlowMonitorImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAppFlowMonitorImpl(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	flows := statusArg.(types.IPFlow)

	// encoding the flows with protobuf format
	pflows := protoEncodeAppFlowMonitorProto(flows)

	// publish protobuf-encoded flowlog to zedcloud
	select {
	case ctx.FlowlogQueue <- pflows:
	default:
		log.Errorf("Flowlog queue is full, dropping flowlog entry: %+v", pflows.Scope)
		ctx.flowLogMetrics.Lock()
		ctx.flowLogMetrics.Messages.Drops++
		ctx.flowLogMetrics.Flows.Drops += uint64(len(pflows.Flows))
		ctx.flowLogMetrics.DNSReqs.Drops += uint64(len(pflows.DnsReqs))
		ctx.flowLogMetrics.Unlock()
	}
}

func handleAppFlowMonitorDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Functionf("handleAppFlowMonitorDelete(%s)", key)
}

func aclActionToProtoAction(action types.ACLActionType) flowlog.ACLAction {
	switch action {
	case types.ACLActionAccept:
		return flowlog.ACLAction_ActionAccept
	case types.ACLActionDrop:
		return flowlog.ACLAction_ActionDrop
	default:
		return flowlog.ACLAction_ActionUnknown
	}
}

func protoEncodeAppFlowMonitorProto(ipflow types.IPFlow) *flowlog.FlowMessage {

	pflows := new(flowlog.FlowMessage)
	pflows.DevId = *proto.String(devUUID.String())

	// ScopeInfo fill in
	pScope := new(flowlog.ScopeInfo)
	pScope.Uuid = ipflow.Scope.UUID.String()
	pScope.Intf = ipflow.Scope.Intf
	pScope.LocalIntf = ipflow.Scope.Localintf
	pScope.NetInstUUID = ipflow.Scope.NetUUID.String()
	pflows.Scope = pScope

	// get the ip flows from the input
	for _, rec := range ipflow.Flows {
		prec := new(flowlog.FlowRecord)

		// IpFlow fill in
		pIpflow := new(flowlog.IpFlow)
		pIpflow.Src = rec.Flow.Src.String()
		pIpflow.Dest = rec.Flow.Dst.String()
		pIpflow.SrcPort = int32(rec.Flow.SrcPort)
		pIpflow.DestPort = int32(rec.Flow.DstPort)
		pIpflow.Protocol = int32(rec.Flow.Proto)
		prec.Flow = pIpflow

		prec.Inbound = rec.Inbound
		prec.AclId = rec.ACLID
		prec.Action = aclActionToProtoAction(rec.Action)
		// prec.AclName =
		pStart := new(timestamp.Timestamp)
		pStart = timeNanoToProto(rec.StartTime)
		prec.StartTime = pStart
		pEnd := new(timestamp.Timestamp)
		pEnd = timeNanoToProto(rec.StopTime)
		prec.EndTime = pEnd
		prec.TxBytes = rec.TxBytes
		prec.TxPkts = rec.TxPkts
		prec.RxBytes = rec.RxBytes
		prec.RxPkts = rec.RxPkts
		pflows.Flows = append(pflows.Flows, prec)
	}

	// get the ip DNS records from the input
	for _, dns := range ipflow.DNSReqs {
		pdns := new(flowlog.DnsRequest)
		pdns.HostName = dns.HostName
		for _, address := range dns.Addrs {
			pdns.Addrs = append(pdns.Addrs, address.String())
		}
		dnsTime := new(timestamp.Timestamp)
		dnsTime = timeNanoToProto(dns.RequestTime)
		pdns.RequestTime = dnsTime
		pdns.AclNum = dns.ACLNum
		pflows.DnsReqs = append(pflows.DnsReqs, pdns)
	}

	return pflows
}

func flowlogTask(ctx *zedagentContext, flowlogQueue <-chan *flowlog.FlowMessage) {
	wdName := agentName + "flowlog"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	var (
		iteration    int
		retryMsg     *flowlog.FlowMessage
		retryAttempt int
		retryTimer   *time.Timer
	)
	publish := func(msg *flowlog.FlowMessage) {
		start := time.Now()
		log.Function("flowlogTask got message")
		var retry bool
		err := publishFlowMessage(msg, iteration)
		if err == nil {
			iteration++
			ctx.flowLogMetrics.Lock()
			ctx.flowLogMetrics.Messages.Success++
			ctx.flowLogMetrics.Flows.Success += uint64(len(msg.Flows))
			ctx.flowLogMetrics.DNSReqs.Success += uint64(len(msg.DnsReqs))
			ctx.flowLogMetrics.Unlock()
		} else {
			log.Error(err)
			ctx.flowLogMetrics.Lock()
			ctx.flowLogMetrics.Messages.FailedAttempts++
			ctx.flowLogMetrics.Flows.FailedAttempts += uint64(len(msg.Flows))
			ctx.flowLogMetrics.DNSReqs.FailedAttempts += uint64(len(msg.DnsReqs))
			ctx.flowLogMetrics.Unlock()
			if (100*len(flowlogQueue))/cap(flowlogQueue) > 90 {
				// More than 90% of the queue is used, start dropping instead of retrying.
				log.Warnf("flowlogTask: dropped flow message: %+v", msg.Scope)
				ctx.flowLogMetrics.Lock()
				ctx.flowLogMetrics.Messages.Drops++
				ctx.flowLogMetrics.Flows.Drops += uint64(len(msg.Flows))
				ctx.flowLogMetrics.DNSReqs.Drops += uint64(len(msg.DnsReqs))
				ctx.flowLogMetrics.Unlock()
			} else {
				retry = true
			}
		}
		if retry {
			// Keep retrying with a truncated exponential backoff.
			retryMsg = msg
			exp := retryAttempt
			const maxExp = 7 // 128 (2^7) seconds is the maximum delay
			if exp > maxExp {
				exp = maxExp
			}
			retryTimer = time.NewTimer((1 << exp) * time.Second)
			retryAttempt++
		} else {
			retryMsg = nil
			retryAttempt = 0
			if retryTimer != nil {
				retryTimer.Stop()
				retryTimer = nil
			}
		}
		log.Function("flowlogTask is done with the message")
		ctx.ps.CheckMaxTimeTopic(wdName, "PublishFlowMessage", start,
			warningTime, errorTime)
	}

	for {
		if retryMsg != nil {
			select {
			case <-retryTimer.C:
				publish(retryMsg)
			case <-stillRunning.C:
			}
		} else {
			select {
			case flowMsg := <-flowlogQueue:
				publish(flowMsg)
			case <-stillRunning.C:
			}
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func publishFlowMessage(flowMsg *flowlog.FlowMessage, iteration int) error {
	data, err := proto.Marshal(flowMsg)
	if err != nil {
		err = fmt.Errorf("publishFlowMessage: proto marshaling error %w", err)
		return err
	}
	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(flowMsg))

	flowlogURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "flowlog")
	const bailOnHTTPErr = false
	_, _, rtf, err := zedcloud.SendOnAllIntf(zedcloudCtx, flowlogURL,
		size, buf, iteration, bailOnHTTPErr)
	if err != nil {
		err = fmt.Errorf("publishFlowMessage: SendOnAllIntf failed with %d: %s",
			rtf, err)
		return err
	}
	writeSentFlowProtoMessage(data)
	return nil
}

func timeNanoToProto(timenum int64) *timestamp.Timestamp {
	timeProto, _ := ptypes.TimestampProto(time.Unix(0, timenum))
	return timeProto
}

func writeSentFlowProtoMessage(contents []byte) {
	writeProtoMessage("lastflowlog", contents)
}

func handleAppContainerMetricsCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleAppContainerMetricsImpl(ctxArg, key, statusArg)
}

func handleAppContainerMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleAppContainerMetricsImpl(ctxArg, key, statusArg)
}

func handleAppContainerMetricsImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	acMetrics := statusArg.(types.AppContainerMetrics)
	log.Tracef("handleAppContainerMetricsImpl(%s), num containers %d",
		key, len(acMetrics.StatsList))
}
