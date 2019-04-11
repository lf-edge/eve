// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle NetworkService responses from zedrouter

package zedagent

import (
	"bytes"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"strings"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Infof("handleNetworkServiceStatusModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkServiceStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleNetworkServiceModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	// XXX look for error; copy to device error; need device error in proto
	// XXX have handlemetrics read sub.GetAll() and look for errors?
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkService error %s\n", status.Error)
	}
	switch status.Type {
	case types.NST_LISP:
		handleNetworkLispServiceStatusModify(ctx, status)
	case types.NST_STRONGSWAN:
		handleNetworkVpnServiceStatusModify(ctx, status)
	default:
	}
	log.Infof("handleNetworkServiceModify(%s) done\n", key)
}

func handleNetworkServiceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkServiceDelete(%s)\n", key)
	status := cast.CastNetworkServiceStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleNetworkServiceDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	// XXX how do we find and delete any error
	ctx := ctxArg.(*zedagentContext)
	switch status.Type {
	case types.NST_LISP:
		handleNetworkLispServiceStatusDelete(ctx, status)
	case types.NST_STRONGSWAN:
		handleNetworkVpnServiceStatusDelete(ctx, status)
	default:
	}
	log.Infof("handleNetworkServiceDelete(%s) done\n", key)
}

func handleNetworkVpnServiceStatusModify(ctx *zedagentContext,
	status types.NetworkServiceStatus) {
	prepareVpnServiceInfoMsg(ctx, status, false)
}

func handleNetworkVpnServiceStatusDelete(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareVpnServiceInfoMsg(ctx, status, true)
}

func prepareAndPublishLispServiceInfoMsg(ctx *zedagentContext,
	status types.NetworkServiceStatus, deleted bool) {
	infoMsg := &zmet.ZInfoMsg{}
	infoType := new(zmet.ZInfoTypes)
	*infoType = zmet.ZInfoTypes_ZiService
	infoMsg.DevId = *proto.String(zcdevUUID.String())
	infoMsg.Ztype = *infoType

	serviceUUID := status.Key()
	svcInfo := new(zmet.ZInfoService)
	svcInfo.ServiceID = serviceUUID
	svcInfo.ServiceName = status.DisplayName
	svcInfo.ServiceType = uint32(status.Type)
	svcInfo.Activated = status.Activated

	// XXX When a service instance is deleted it is ideal to send
	// a flag such as deleted/gone inside ZInfoService message.
	// Having a separate flag (indicating deletion) make is explicit
	// and easy for the cloud process.
	// For now we just send an empty lispInfo to indicate deletion to cloud.
	// It can't be omitted since protobuf requires something to satisfy
	// the oneof.

	lispInfo := new(zmet.ZInfoLisp)
	lispStatus := status.LispInfoStatus
	if lispStatus != nil && !deleted {
		lispInfo.ItrCryptoPort = lispStatus.ItrCryptoPort
		lispInfo.EtrNatPort = lispStatus.EtrNatPort
		for _, intf := range lispStatus.Interfaces {
			lispInfo.Interfaces = append(lispInfo.Interfaces, intf)
		}

		// Copy ITR database map entries
		for _, dbMap := range lispStatus.DatabaseMaps {
			dbMapEntry := &zmet.DatabaseMap{
				IID: dbMap.IID,
			}

			for _, mapEntry := range dbMap.MapCacheEntries {
				mapCacheEntry := &zmet.MapCacheEntry{
					EID: mapEntry.EID.String(),
				}

				for _, rloc := range mapEntry.Rlocs {
					rlocEntry := &zmet.RlocState{
						Rloc:      rloc.Rloc.String(),
						Reachable: rloc.Reachable,
					}
					mapCacheEntry.Rlocs = append(mapCacheEntry.Rlocs, rlocEntry)
				}
				dbMapEntry.MapCacheEntries = append(dbMapEntry.MapCacheEntries, mapCacheEntry)
			}
			lispInfo.DatabaseMaps = append(lispInfo.DatabaseMaps, dbMapEntry)
		}

		// Copy ETR decap entries
		for _, decapKey := range lispStatus.DecapKeys {
			decap := &zmet.DecapKey{
				Rloc:     decapKey.Rloc.String(),
				Port:     decapKey.Port,
				KeyCount: decapKey.KeyCount,
			}
			lispInfo.DecapKeys = append(lispInfo.DecapKeys, decap)
		}
	}

	svcInfo.InfoContent = new(zmet.ZInfoService_Linfo)
	if x, ok := svcInfo.GetInfoContent().(*zmet.ZInfoService_Linfo); ok {
		x.Linfo = lispInfo
	}

	infoMsg.InfoContent = new(zmet.ZInfoMsg_Sinfo)
	if x, ok := infoMsg.GetInfoContent().(*zmet.ZInfoMsg_Sinfo); ok {
		x.Sinfo = svcInfo
	}
	log.Debugf("Publish LispInfo message to zedcloud: %v\n", infoMsg)
	publishInfo(ctx, serviceUUID, infoMsg)
}

func handleNetworkLispServiceStatusModify(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareAndPublishLispServiceInfoMsg(ctx, status, false)
}

func handleNetworkLispServiceStatusDelete(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareAndPublishLispServiceInfoMsg(ctx, status, true)
}

func prepareVpnServiceInfoMsg(ctx *zedagentContext, status types.NetworkServiceStatus, delete bool) {
	if status.VpnStatus == nil {
		return
	}
	infoMsg := &zmet.ZInfoMsg{}
	infoType := new(zmet.ZInfoTypes)
	*infoType = zmet.ZInfoTypes_ZiService
	infoMsg.DevId = *proto.String(zcdevUUID.String())
	infoMsg.Ztype = *infoType

	serviceUUID := status.Key()
	vpnStatus := status.VpnStatus
	svcInfo := new(zmet.ZInfoService)
	svcInfo.ServiceID = serviceUUID
	svcInfo.ServiceName = status.DisplayName
	svcInfo.ServiceType = uint32(status.Type)
	svcInfo.SoftwareList = new(zmet.ZInfoSW)
	svcInfo.SoftwareList.SwVersion = vpnStatus.Version
	svcInfo.Activated = status.Activated
	upTime, _ := ptypes.TimestampProto(vpnStatus.UpTime)
	svcInfo.UpTimeStamp = upTime
	if !status.ErrorTime.IsZero() {
		errInfo := new(zmet.ErrorInfo)
		errInfo.Description = status.Error
		errTime, _ := ptypes.TimestampProto(status.ErrorTime)
		errInfo.Timestamp = errTime
		svcInfo.SvcErr = append(svcInfo.SvcErr, errInfo)
	}

	vpnInfo := new(zmet.ZInfoVpn)
	vpnInfo.PolicyBased = vpnStatus.PolicyBased
	listeningIpAddrs := strings.Split(vpnStatus.IpAddrs, " ")
	vpnInfo.ListeningIpAddrs = make([]string, len(listeningIpAddrs))
	for idx, ipAddr := range listeningIpAddrs {
		vpnInfo.ListeningIpAddrs[idx] = ipAddr
	}

	totalConnCount := len(vpnStatus.StaleVpnConns) + len(vpnStatus.ActiveVpnConns)

	if totalConnCount == 0 {
		svcInfo.InfoContent = new(zmet.ZInfoService_Vinfo)
		if x, ok := svcInfo.GetInfoContent().(*zmet.ZInfoService_Vinfo); ok {
			x.Vinfo = vpnInfo
		}

		// prapare the final stuff
		infoMsg.InfoContent = new(zmet.ZInfoMsg_Sinfo)
		if x, ok := infoMsg.GetInfoContent().(*zmet.ZInfoMsg_Sinfo); ok {
			x.Sinfo = svcInfo
		}
		publishInfo(ctx, serviceUUID, infoMsg)
		return
	}

	vpnInfo.Conn = make([]*zmet.ZInfoVpnConn, totalConnCount)
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

	svcInfo.InfoContent = new(zmet.ZInfoService_Vinfo)
	if x, ok := svcInfo.GetInfoContent().(*zmet.ZInfoService_Vinfo); ok {
		x.Vinfo = vpnInfo
	}

	// prepare the final stuff
	infoMsg.InfoContent = new(zmet.ZInfoMsg_Sinfo)
	if x, ok := infoMsg.GetInfoContent().(*zmet.ZInfoMsg_Sinfo); ok {
		x.Sinfo = svcInfo
	}
	publishInfo(ctx, serviceUUID, infoMsg)
}

func publishVpnConnection(vpnInfo *zmet.ZInfoVpn,
	vpnConn *types.VpnConnStatus) *zmet.ZInfoVpnConn {
	if vpnConn == nil {
		return nil
	}
	vpnConnInfo := new(zmet.ZInfoVpnConn)
	vpnConnInfo.Id = vpnConn.Id
	vpnConnInfo.Name = vpnConn.Name
	vpnConnInfo.State = zmet.ZInfoVpnState(vpnConn.State)
	vpnConnInfo.Ikes = vpnConn.Ikes
	vpnConnInfo.EstTime = vpnConn.EstTime
	vpnConnInfo.Version = vpnConn.Version

	lEndPointInfo := new(zmet.ZInfoVpnEndPoint)
	lEndPointInfo.Id = vpnConn.LInfo.Id
	lEndPointInfo.IpAddr = vpnConn.LInfo.IpAddr
	lEndPointInfo.Port = vpnConn.LInfo.Port
	vpnConnInfo.LInfo = lEndPointInfo

	rEndPointInfo := new(zmet.ZInfoVpnEndPoint)
	rEndPointInfo.Id = vpnConn.RInfo.Id
	rEndPointInfo.IpAddr = vpnConn.RInfo.IpAddr
	rEndPointInfo.Port = vpnConn.RInfo.Port
	vpnConnInfo.RInfo = rEndPointInfo

	if len(vpnConn.Links) == 0 {
		return vpnConnInfo
	}
	vpnConnInfo.Links = make([]*zmet.ZInfoVpnLink, len(vpnConn.Links))

	for idx, linkData := range vpnConn.Links {
		linkInfo := new(zmet.ZInfoVpnLink)
		linkInfo.Id = linkData.Id
		linkInfo.ReqId = linkData.ReqId
		linkInfo.InstTime = linkData.InstTime
		linkInfo.EspInfo = linkData.EspInfo
		linkInfo.State = zmet.ZInfoVpnState(linkData.State)

		linfo := new(zmet.ZInfoVpnLinkInfo)
		linfo.SubNet = linkData.LInfo.SubNet
		linfo.SpiId = linkData.LInfo.SpiId
		linfo.Direction = linkData.LInfo.Direction
		linkInfo.LInfo = linfo

		rinfo := new(zmet.ZInfoVpnLinkInfo)
		rinfo.SubNet = linkData.RInfo.SubNet
		rinfo.SpiId = linkData.RInfo.SpiId
		rinfo.Direction = linkData.RInfo.Direction
		linkInfo.RInfo = rinfo

		vpnConnInfo.Links[idx] = linkInfo
	}

	return vpnConnInfo
}

func publishInfo(ctx *zedagentContext, UUID string, infoMsg *zmet.ZInfoMsg) {
	publishInfoToZedCloud(UUID, infoMsg, ctx.iteration)
	ctx.iteration += 1
}

func publishInfoToZedCloud(UUID string, infoMsg *zmet.ZInfoMsg, iteration int) {

	log.Infof("publishNetworkServiceInfoToZedCloud sending %v\n", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishNetworkServiceInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := serverName + "/" + statusApi
	zedcloud.RemoveDeferred(UUID)
	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(infoMsg))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("publishNetworkServiceInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(UUID, buf, size, statusUrl,
			zedcloudCtx, true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}

func handleNetworkServiceMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Debugf("handleNetworkServiceMetricsModify(%s)\n", key)
	metrics := cast.CastNetworkServiceMetrics(statusArg)
	if metrics.Key() != key {
		log.Errorf("handleNetworkServiceMetricsModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, metrics.Key(), metrics)
		return
	}
	log.Debugf("handleNetworkServiceMetricsModify(%s) done\n", key)
}

func handleNetworkServiceMetricsDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkServiceMetricsDelete(%s)\n", key)
	metrics := cast.CastNetworkServiceMetrics(statusArg)
	if metrics.Key() != key {
		log.Errorf("handleNetworkServiceMetricsDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, metrics.Key(), metrics)
		return
	}
	log.Infof("handleNetworkServiceMetricsDelete(%s) done\n", key)
}

func createNetworkServiceMetrics(ctx *zedagentContext, reportMetrics *zmet.ZMetricMsg) {

	sub := ctx.subNetworkServiceMetrics
	metlist := sub.GetAll()
	if metlist == nil || len(metlist) == 0 {
		return
	}
	for _, met := range metlist {
		metrics := cast.CastNetworkServiceMetrics(met)
		metricService := protoEncodeNetworkServiceMetricProto(metrics)
		reportMetrics.Sm = append(reportMetrics.Sm, metricService)
	}
	log.Debugln("network service metrics: ", reportMetrics.Sm)
}

func protoEncodeNetworkServiceMetricProto(status types.NetworkServiceMetrics) *zmet.ZMetricService {

	serviceMetric := new(zmet.ZMetricService)
	serviceMetric.ServiceID = status.Key()
	serviceMetric.ServiceName = status.DisplayName
	serviceMetric.ServiceType = uint32(status.Type)
	switch status.Type {
	case types.NST_STRONGSWAN:
		protoEncodeVpnServiceMetric(status, serviceMetric)

	case types.NST_LISP:
		log.Debugf("Publish Lisp Service Metric to Zedcloud %v\n",
			serviceMetric)
		protoEncodeLispServiceMetric(status, serviceMetric)
	}

	return serviceMetric
}

func protoEncodeLispServiceMetric(status types.NetworkServiceMetrics,
	serviceMetric *zmet.ZMetricService) {
	if status.LispMetrics == nil {
		return
	}
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
	serviceMetric.LispGlobalStats = lispGlobalMetric

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
	serviceMetric.FlowStats = flowStats

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

	serviceMetric.ServiceContent = new(zmet.ZMetricService_Lispm)
	if x, ok := serviceMetric.GetServiceContent().(*zmet.ZMetricService_Lispm); ok {
		x.Lispm = lispMetric
	}
}

func protoEncodeVpnServiceMetric(metrics types.NetworkServiceMetrics,
	serviceMetrics *zmet.ZMetricService) {
	if metrics.VpnMetrics == nil {
		return
	}

	stats := metrics.VpnMetrics
	vpnMetric := new(zmet.ZMetricVpn)
	vpnMetric.ConnStat = protoEncodeVpnServiceStat(stats.DataStat)
	vpnMetric.NatTStat = protoEncodeVpnServiceStat(stats.NatTStat)
	vpnMetric.IkeStat = protoEncodeVpnServiceStat(stats.IkeStat)
	vpnMetric.EspStat = protoEncodeVpnServiceStat(stats.EspStat)
	serviceMetrics.ServiceContent = new(zmet.ZMetricService_Vpnm)
	if x, ok := serviceMetrics.GetServiceContent().(*zmet.ZMetricService_Vpnm); ok {
		x.Vpnm = vpnMetric
	}
	protoEncodeVpnServiceFlowMetric(metrics, serviceMetrics)
}

func protoEncodeVpnServiceStat(stats types.LinkPktStats) *zmet.ZMetricConn {
	connStat := new(zmet.ZMetricConn)
	connStat.InPkts = new(zmet.PktStat)
	connStat.OutPkts = new(zmet.PktStat)
	connStat.InPkts.Packets = stats.InPkts.Pkts
	connStat.InPkts.Bytes = stats.InPkts.Bytes
	connStat.OutPkts.Packets = stats.OutPkts.Pkts
	connStat.OutPkts.Bytes = stats.OutPkts.Bytes
	return connStat
}

func protoEncodeVpnServiceFlowMetric(metrics types.NetworkServiceMetrics,
	serviceMetrics *zmet.ZMetricService) {
	if len(metrics.VpnMetrics.VpnConns) == 0 {
		return
	}

	vpnMetrics := metrics.VpnMetrics
	serviceMetrics.FlowStats = make([]*zmet.ZMetricFlow,
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
		serviceMetrics.FlowStats[idx] = flowStats
	}
}
