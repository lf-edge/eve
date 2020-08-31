// Copyright (c) 2018,2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkInstanceStatus from zedrouter

package zedagent

import (
	"bytes"
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

var flowIteration int

func handleNetworkInstanceModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Infof("handleNetworkInstanceStatusModify(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.NetworkInstanceStatus)
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkInstance error %s",
			status.Error)
	}
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, false)
	log.Infof("handleNetworkInstanceModify(%s) done", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkInstanceDelete(%s)", key)
	status := statusArg.(types.NetworkInstanceStatus)
	ctx := ctxArg.(*zedagentContext)
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, true)
	log.Infof("handleNetworkInstanceDelete(%s) done", key)
}

func prepareAndPublishNetworkInstanceInfoMsg(ctx *zedagentContext,
	status types.NetworkInstanceStatus, deleted bool) {

	infoMsg := &zinfo.ZInfoMsg{}
	infoType := new(zinfo.ZInfoTypes)
	*infoType = zinfo.ZInfoTypes_ZiNetworkInstance
	infoMsg.DevId = *proto.String(zcdevUUID.String())
	infoMsg.Ztype = *infoType
	infoMsg.AtTimeStamp = ptypes.TimestampNow()

	uuid := status.Key()
	info := new(zinfo.ZInfoNetworkInstance)
	info.NetworkID = uuid
	info.NetworkVersion = status.UUIDandVersion.Version
	info.Displayname = status.DisplayName
	info.InstType = uint32(status.Type)
	info.CurrentUplinkIntf = status.CurrentUplinkIntf

	if !status.ErrorTime.IsZero() {
		errInfo := new(zinfo.ErrorInfo)
		errInfo.Description = status.Error
		errTime, _ := ptypes.TimestampProto(status.ErrorTime)
		errInfo.Timestamp = errTime
		info.NetworkErr = append(info.NetworkErr, errInfo)
	}

	if deleted {
		// XXX When a network instance is deleted it is ideal to
		// send a flag such as deleted/gone inside
		// ZInfoNetworkInstance message. Having a separate flag
		// (indicating deletion) would make is explicit
		// and easy for the cloud process.
		info.Activated = false
	} else {
		info.Activated = status.Activated

		info.BridgeNum = uint32(status.BridgeNum)
		info.BridgeName = status.BridgeName
		info.BridgeIPAddr = status.BridgeIPAddr

		for mac, ip := range status.IPAssignments {
			assignment := new(zinfo.ZmetIPAssignmentEntry)
			assignment.MacAddress = mac
			assignment.IpAddress = append(assignment.IpAddress, ip.String())
			info.IpAssignments = append(info.IpAssignments,
				assignment)
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
		info.Ipv4Eid = status.Ipv4Eid
		for _, ifname := range status.IfNameList {
			ia := ctx.assignableAdapters.LookupIoBundleIfName(ifname)
			if ia == nil {
				log.Warnf("Missing adapter for ifname %s", ifname)
				continue
			}
			reportAA := new(zinfo.ZioBundle)
			reportAA.Type = zcommon.PhyIoType(ia.Type)
			reportAA.Name = ia.Phylabel
			reportAA.UsedByAppUUID = zcdevUUID.String()
			list := ctx.assignableAdapters.LookupIoBundleAny(ia.Phylabel)
			for _, ib := range list {
				if ib == nil {
					continue
				}
				reportAA.Members = append(reportAA.Members, ib.Phylabel)
				if ib.MacAddr != "" {
					reportMac := new(zinfo.IoAddresses)
					reportMac.MacAddress = ib.MacAddr
					reportAA.IoAddressList = append(reportAA.IoAddressList,
						reportMac)
				}
				log.Debugf("AssignableAdapters for %s macs %v",
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
	log.Debugf("Publish NetworkInstance Info message to zedcloud: %v",
		infoMsg)
	publishInfo(ctx, uuid, infoMsg)
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

func handleNetworkInstanceMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Debugf("handleNetworkInstanceMetricsModify(%s)", key)
}

func handleNetworkInstanceMetricsDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkInstanceMetricsDelete(%s)", key)
}

func createNetworkInstanceMetrics(ctx *zedagentContext, reportMetrics *zmet.ZMetricMsg) {

	sub := ctx.subNetworkInstanceMetrics
	metlist := sub.GetAll()
	if metlist == nil || len(metlist) == 0 {
		return
	}
	for _, met := range metlist {
		metrics := met.(types.NetworkInstanceMetrics)
		metricInstance := protoEncodeNetworkInstanceMetricProto(metrics)
		reportMetrics.Nm = append(reportMetrics.Nm, metricInstance)
	}
	log.Debugln("network instance metrics: ", reportMetrics.Nm)
}

func protoEncodeNetworkInstanceMetricProto(status types.NetworkInstanceMetrics) *zmet.ZMetricNetworkInstance {

	metric := new(zmet.ZMetricNetworkInstance)
	metric.NetworkID = status.Key()
	metric.NetworkVersion = status.UUIDandVersion.Version
	metric.Displayname = status.DisplayName
	metric.InstType = uint32(status.Type)
	switch status.Type {
	case types.NetworkInstanceTypeCloud:
		protoEncodeVpnInstanceMetric(status, metric)

	default:
		protoEncodeGenericInstanceMetric(status, metric)
	}

	return metric
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

func publishInfo(ctx *zedagentContext, UUID string, infoMsg *zinfo.ZInfoMsg) {
	publishInfoToZedCloud(UUID, infoMsg, ctx.iteration)
	ctx.iteration += 1
}

func publishInfoToZedCloud(UUID string, infoMsg *zinfo.ZInfoMsg, iteration int) {

	log.Infof("publishInfoToZedCloud sending %v", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "info")
	zedcloud.RemoveDeferred(zedcloudCtx, UUID)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(infoMsg))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("publishInfoToZedCloud failed: %s", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(zedcloudCtx, UUID, buf, size, statusUrl,
			true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}

func handleAppFlowMonitorModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleAppFlowMonitorModify(%s)", key)
	flows := statusArg.(types.IPFlow)

	// encoding the flows with protobuf format
	pflows := protoEncodeAppFlowMonitorProto(flows)

	// send protobuf to zedcloud
	sendFlowProtobuf(pflows)
}

func handleAppFlowMonitorDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleAppFlowMonitorDelete(%s)", key)
}

func handleAppVifIPTrigModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleAppVifIPTrigModify(%s)", key)
	ctx := ctxArg.(*zedagentContext)
	trig := statusArg.(types.VifIPTrig)
	findVifAndTrigAppInfoUpload(ctx, trig.MacAddr, trig.IPAddr)
}

func findVifAndTrigAppInfoUpload(ctx *zedagentContext, macAddr string, ipAddr net.IP) {
	sub := ctx.getconfigCtx.subAppInstanceStatus
	items := sub.GetAll()

	for _, st := range items {
		aiStatus := st.(types.AppInstanceStatus)
		log.Debugf("findVifAndTrigAppInfoUpload: mac address %s match, ip %v, publish the info to cloud", macAddr, ipAddr)
		uuidStr := aiStatus.Key()
		aiStatusPtr := &aiStatus
		if aiStatusPtr.MaybeUpdateAppIPAddr(macAddr, ipAddr.String()) {
			log.Infof("findVifAndTrigAppInfoUpload: underlay %v", aiStatusPtr.UnderlayNetworks)
			PublishAppInfoToZedCloud(ctx, uuidStr, aiStatusPtr, ctx.assignableAdapters, ctx.iteration)
			ctx.iteration++
			break
		}
	}
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
	pflows.DevId = ipflow.DevID.String()

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

func sendFlowProtobuf(protoflows *flowlog.FlowMessage) {

	flowQ.PushBack(protoflows)

	for flowQ.Len() > 0 {
		ent := flowQ.Front()
		pflowsPtr := ent.Value.(*flowlog.FlowMessage)

		data, err := proto.Marshal(pflowsPtr)
		if err != nil {
			log.Errorf("FlowStats: SendFlowProtobuf proto marshaling error %v", err) // XXX change to fatal
		}

		flowIteration++
		buf := bytes.NewBuffer(data)
		size := int64(proto.Size(pflowsPtr))
		flowlogURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "flowlog")
		const bailOnHTTPErr = false
		_, _, rtf, err := zedcloud.SendOnAllIntf(zedcloudCtx, flowlogURL,
			size, buf, flowIteration, bailOnHTTPErr)
		if err != nil {
			log.Errorf("FlowStats: sendFlowProtobuf status %d failed: %s",
				rtf, err)
			flowIteration--
			if flowQ.Len() > 100 { // if fail to send for too long, start to drop
				flowQ.Remove(ent)
			}
			return
		}

		log.Debugf("Send Flow protobuf out on all intfs, message size %d, flowQ size %d",
			size, flowQ.Len())
		writeSentFlowProtoMessage(data)

		flowQ.Remove(ent)
	}
}

func timeNanoToProto(timenum int64) *timestamp.Timestamp {
	timeProto, _ := ptypes.TimestampProto(time.Unix(0, timenum))
	return timeProto
}

func writeSentFlowProtoMessage(contents []byte) {
	writeProtoMessage("lastflowlog", contents)
}

func handleAppContainerMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	acMetrics := statusArg.(types.AppContainerMetrics)
	log.Debugf("handleAppContainerMetricsModify(%s), num containers %d", key, len(acMetrics.StatsList))
}
