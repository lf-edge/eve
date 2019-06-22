// Copyright (c) 2018,2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkInstanceStatus from zedrouter

package zedagent

import (
	"bytes"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	zinfo "github.com/lf-edge/eve/api/go/info"   // XXX need to stop using
	zmet "github.com/lf-edge/eve/api/go/metrics" // zinfo and zmet here
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
)

func handleNetworkInstanceModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Infof("handleNetworkInstanceStatusModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkInstanceStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleNetworkInstanceModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkInstance error %s\n",
			status.Error)
	}
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, false)
	log.Infof("handleNetworkInstanceModify(%s) done\n", key)
}

func handleNetworkInstanceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkInstanceDelete(%s)\n", key)
	status := cast.CastNetworkInstanceStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleNetworkInstanceDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedagentContext)
	prepareAndPublishNetworkInstanceInfoMsg(ctx, status, true)
	log.Infof("handleNetworkInstanceDelete(%s) done\n", key)
}

func prepareAndPublishNetworkInstanceInfoMsg(ctx *zedagentContext,
	status types.NetworkInstanceStatus, deleted bool) {

	infoMsg := &zinfo.ZInfoMsg{}
	infoType := new(zinfo.ZInfoTypes)
	*infoType = zinfo.ZInfoTypes_ZiNetworkInstance
	infoMsg.DevId = *proto.String(zcdevUUID.String())
	infoMsg.Ztype = *infoType

	uuid := status.Key()
	info := new(zinfo.ZInfoNetworkInstance)
	info.NetworkID = uuid
	info.NetworkVersion = status.UUIDandVersion.Version
	info.Displayname = status.DisplayName
	info.InstType = uint32(status.Type)

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

		// For now we just send an empty lispInfo to indicate deletion to cloud.
		// It can't be omitted since protobuf requires something to satisfy
		// the oneof.
		if status.LispInfoStatus != nil {
			fillLispInfo(info, status.LispInfoStatus)
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
	log.Debugf("Publish NetworkInstance Info message to zedcloud: %v\n",
		infoMsg)
	publishInfo(ctx, uuid, infoMsg)
}

func fillLispInfo(info *zinfo.ZInfoNetworkInstance, lispStatus *types.LispInfoStatus) {

	lispInfo := new(zinfo.ZInfoLisp)

	lispInfo.ItrCryptoPort = lispStatus.ItrCryptoPort
	lispInfo.EtrNatPort = lispStatus.EtrNatPort
	for _, intf := range lispStatus.Interfaces {
		lispInfo.Interfaces = append(lispInfo.Interfaces, intf)
	}

	// Copy ITR database map entries
	for _, dbMap := range lispStatus.DatabaseMaps {
		dbMapEntry := &zinfo.DatabaseMap{
			IID: dbMap.IID,
		}

		for _, mapEntry := range dbMap.MapCacheEntries {
			mapCacheEntry := &zinfo.MapCacheEntry{
				EID: mapEntry.EID.String(),
			}

			for _, rloc := range mapEntry.Rlocs {
				rlocEntry := &zinfo.RlocState{
					Rloc:      rloc.Rloc.String(),
					Reachable: rloc.Reachable,
				}
				mapCacheEntry.Rlocs = append(mapCacheEntry.Rlocs,
					rlocEntry)
			}
			dbMapEntry.MapCacheEntries = append(dbMapEntry.MapCacheEntries,
				mapCacheEntry)
		}
		lispInfo.DatabaseMaps = append(lispInfo.DatabaseMaps,
			dbMapEntry)
	}

	// Copy ETR decap entries
	for _, decapKey := range lispStatus.DecapKeys {
		decap := &zinfo.DecapKey{
			Rloc:     decapKey.Rloc.String(),
			Port:     decapKey.Port,
			KeyCount: decapKey.KeyCount,
		}
		lispInfo.DecapKeys = append(lispInfo.DecapKeys, decap)
	}

	info.InfoContent = new(zinfo.ZInfoNetworkInstance_Linfo)
	if x, ok := info.GetInfoContent().(*zinfo.ZInfoNetworkInstance_Linfo); ok {
		x.Linfo = lispInfo
	}
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

	log.Debugf("handleNetworkInstanceMetricsModify(%s)\n", key)
	metrics := cast.CastNetworkInstanceMetrics(statusArg)
	if metrics.Key() != key {
		log.Errorf("handleNetworkInstanceMetricsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, metrics.Key(), metrics)
		return
	}
	log.Debugf("handleNetworkInstanceMetricsModify(%s) done\n", key)
}

func handleNetworkInstanceMetricsDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkInstanceMetricsDelete(%s)\n", key)
	metrics := cast.CastNetworkInstanceMetrics(statusArg)
	if metrics.Key() != key {
		log.Errorf("handleNetworkInstanceMetricsDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, metrics.Key(), metrics)
		return
	}
	log.Infof("handleNetworkInstanceMetricsDelete(%s) done\n", key)
}

func createNetworkInstanceMetrics(ctx *zedagentContext, reportMetrics *zmet.ZMetricMsg) {

	sub := ctx.subNetworkInstanceMetrics
	metlist := sub.GetAll()
	if metlist == nil || len(metlist) == 0 {
		return
	}
	for _, met := range metlist {
		metrics := cast.CastNetworkInstanceMetrics(met)
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

	case types.NetworkInstanceTypeMesh: // XXX any subtype?
		log.Debugf("Publish Lisp Instance Metric to Zedcloud %v\n",
			metric)
		protoEncodeLispInstanceMetric(status, metric)
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

func protoEncodeLispInstanceMetric(status types.NetworkInstanceMetrics,
	metric *zmet.ZMetricNetworkInstance) {
	if status.LispMetrics == nil {
		return
	}
	protoEncodeGenericInstanceMetric(status, metric)
	metrics := status.LispMetrics

	lispGlobalMetric := new(zmet.ZMetricLispGlobal)
	lispGlobalMetric.ItrPacketSendError = &zmet.PktStat{
		Packets: metrics.ItrPacketSendError.Pkts,
		Bytes:   metrics.ItrPacketSendError.Bytes,
	}
	lispGlobalMetric.InvalidEidError = &zmet.PktStat{
		Packets: metrics.InvalidEidError.Pkts,
		Bytes:   metrics.InvalidEidError.Bytes,
	}
	lispGlobalMetric.NoDecryptKey = &zmet.PktStat{
		Packets: metrics.NoDecryptKey.Pkts,
		Bytes:   metrics.NoDecryptKey.Bytes,
	}
	lispGlobalMetric.OuterHeaderError = &zmet.PktStat{
		Packets: metrics.OuterHeaderError.Pkts,
		Bytes:   metrics.OuterHeaderError.Bytes,
	}
	lispGlobalMetric.BadInnerVersion = &zmet.PktStat{
		Packets: metrics.BadInnerVersion.Pkts,
		Bytes:   metrics.BadInnerVersion.Bytes,
	}
	lispGlobalMetric.GoodPackets = &zmet.PktStat{
		Packets: metrics.GoodPackets.Pkts,
		Bytes:   metrics.GoodPackets.Bytes,
	}
	lispGlobalMetric.ICVError = &zmet.PktStat{
		Packets: metrics.ICVError.Pkts,
		Bytes:   metrics.ICVError.Bytes,
	}
	lispGlobalMetric.LispHeaderError = &zmet.PktStat{
		Packets: metrics.LispHeaderError.Pkts,
		Bytes:   metrics.LispHeaderError.Bytes,
	}
	lispGlobalMetric.CheckSumError = &zmet.PktStat{
		Packets: metrics.CheckSumError.Pkts,
		Bytes:   metrics.CheckSumError.Bytes,
	}
	lispGlobalMetric.DecapReInjectError = &zmet.PktStat{
		Packets: metrics.DecapReInjectError.Pkts,
		Bytes:   metrics.DecapReInjectError.Bytes,
	}
	lispGlobalMetric.DecryptError = &zmet.PktStat{
		Packets: metrics.DecryptError.Pkts,
		Bytes:   metrics.DecryptError.Bytes,
	}
	metric.LispGlobalStats = lispGlobalMetric

	flowStats := []*zmet.ZMetricFlow{}

	for _, eidStat := range metrics.EidStats {
		iid := eidStat.IID
		metricFlow := &zmet.ZMetricFlow{
			Iid: iid,
		}
		lEndPoint := &zmet.ZMetricFlowEndPoint{}
		flowLinks := []*zmet.ZMetricFlowLink{}
		for _, eidMap := range metrics.EidMaps {
			for _, eid := range eidMap.Eids {
				flowLink := &zmet.ZMetricFlowLink{}
				flowLink.Link = new(zmet.ZMetricFlowLink_Eid)
				if x, ok := flowLink.GetLink().(*zmet.ZMetricFlowLink_Eid); ok {
					x.Eid = eid.String()
				}
				flowLinks = append(flowLinks, flowLink)
			}
		}
		lEndPoint.Link = flowLinks
		metricFlow.LEndPoint = lEndPoint

		rEndPoint := []*zmet.ZMetricFlowEndPoint{}
		eid := eidStat.Eid
		for _, rlocStat := range eidStat.RlocStats {
			rloc := rlocStat.Rloc
			stat := rlocStat.Stats
			flowEndPoint := &zmet.ZMetricFlowEndPoint{}
			flowEndPoint.Stats = &zmet.PktStat{
				Packets: stat.Pkts,
				Bytes:   stat.Bytes,
			}
			flowEndPoint.Endpoint = new(zmet.ZMetricFlowEndPoint_Rloc)
			if x, ok := flowEndPoint.GetEndpoint().(*zmet.ZMetricFlowEndPoint_Rloc); ok {
				x.Rloc = rloc.String()
			}
			flowLinks := []*zmet.ZMetricFlowLink{}
			flowLink := &zmet.ZMetricFlowLink{}
			flowLink.Link = new(zmet.ZMetricFlowLink_Eid)
			if x, ok := flowLink.GetLink().(*zmet.ZMetricFlowLink_Eid); ok {
				x.Eid = eid.String()
			}
			flowLinks = append(flowLinks, flowLink)
			flowEndPoint.Link = flowLinks

			rEndPoint = append(rEndPoint, flowEndPoint)
		}
		metricFlow.REndPoint = rEndPoint
		flowStats = append(flowStats, metricFlow)
	}
	metric.FlowStats = flowStats

	// Fill lisp metric stats also for now.
	// We can deprecate the same later
	lispMetric := new(zmet.ZMetricLisp)
	lispMetric.ItrPacketSendError = &zmet.PktStat{
		Packets: metrics.ItrPacketSendError.Pkts,
		Bytes:   metrics.ItrPacketSendError.Bytes,
	}
	lispMetric.InvalidEidError = &zmet.PktStat{
		Packets: metrics.InvalidEidError.Pkts,
		Bytes:   metrics.InvalidEidError.Bytes,
	}
	lispMetric.NoDecryptKey = &zmet.PktStat{
		Packets: metrics.NoDecryptKey.Pkts,
		Bytes:   metrics.NoDecryptKey.Bytes,
	}
	lispMetric.OuterHeaderError = &zmet.PktStat{
		Packets: metrics.OuterHeaderError.Pkts,
		Bytes:   metrics.OuterHeaderError.Bytes,
	}
	lispMetric.BadInnerVersion = &zmet.PktStat{
		Packets: metrics.BadInnerVersion.Pkts,
		Bytes:   metrics.BadInnerVersion.Bytes,
	}
	lispMetric.GoodPackets = &zmet.PktStat{
		Packets: metrics.GoodPackets.Pkts,
		Bytes:   metrics.GoodPackets.Bytes,
	}
	lispMetric.ICVError = &zmet.PktStat{
		Packets: metrics.ICVError.Pkts,
		Bytes:   metrics.ICVError.Bytes,
	}
	lispMetric.LispHeaderError = &zmet.PktStat{
		Packets: metrics.LispHeaderError.Pkts,
		Bytes:   metrics.LispHeaderError.Bytes,
	}
	lispMetric.CheckSumError = &zmet.PktStat{
		Packets: metrics.CheckSumError.Pkts,
		Bytes:   metrics.CheckSumError.Bytes,
	}
	lispMetric.DecapReInjectError = &zmet.PktStat{
		Packets: metrics.DecapReInjectError.Pkts,
		Bytes:   metrics.DecapReInjectError.Bytes,
	}
	lispMetric.DecryptError = &zmet.PktStat{
		Packets: metrics.DecryptError.Pkts,
		Bytes:   metrics.DecryptError.Bytes,
	}

	lispStats := []*zmet.EidStats{}
	for _, eidStat := range metrics.EidStats {
		lispStat := &zmet.EidStats{
			IID: eidStat.IID,
			EID: eidStat.Eid.String(),
		}

		rlocStats := []*zmet.RlocStats{}
		for _, rloc := range eidStat.RlocStats {
			rlocStat := &zmet.RlocStats{
				Rloc: rloc.Rloc.String(),
				Stats: &zmet.PktStat{
					Packets: rloc.Stats.Pkts,
					Bytes:   rloc.Stats.Bytes,
				},
				SecondsSinceLastPacket: rloc.SecondsSinceLastPacket,
			}
			rlocStats = append(rlocStats, rlocStat)
		}
		lispStat.RlocStatsEntries = rlocStats
		lispStats = append(lispStats, lispStat)
	}
	lispMetric.EidStatsEntries = lispStats

	metric.InstanceContent = new(zmet.ZMetricNetworkInstance_Lispm)
	if x, ok := metric.GetInstanceContent().(*zmet.ZMetricNetworkInstance_Lispm); ok {
		x.Lispm = lispMetric
	}
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

	log.Infof("publishInfoToZedCloud sending %v\n", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := serverName + "/" + statusApi
	zedcloud.RemoveDeferred(UUID)
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(infoMsg))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("publishInfoToZedCloud failed: %s\n", err)
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred(UUID, buf, size, statusUrl,
			zedcloudCtx, true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}
