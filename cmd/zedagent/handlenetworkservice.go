// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService responses from zedrouter

package zedagent

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"log"
	"strings"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Printf("handleNetworkServiceStatusModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkServiceStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleNetworkServiceModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	// XXX look for error; copy to device error; need device error in proto
	// XXX have handlemetrics read sub.GetAll() and look for errors?
	if !status.ErrorTime.IsZero() {
		log.Printf("Received NetworkService error %s\n", status.Error)
	}
	switch status.Type {
	case types.NST_LISP:
		handleNetworkLispServiceStatusModify(ctx, status)
	case types.NST_STRONGSWAN:
		handleNetworkVpnServiceStatusModify(ctx, status)
	default:
	}
	log.Printf("handleNetworkServiceModify(%s) done\n", key)
}

func handleNetworkServiceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleNetworkServiceDelete(%s)\n", key)
	status := cast.CastNetworkServiceStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleNetworkServiceDelete key/UUID mismatch %s vs %s; ignored %+v\n",
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
	log.Printf("handleNetworkServiceDelete(%s) done\n", key)
}

func handleNetworkVpnServiceStatusModify(ctx *zedagentContext,
	status types.NetworkServiceStatus) {
	prepareVpnServiceInfoMsg(ctx, status, false)
}

func handleNetworkVpnServiceStatusDelete(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareVpnServiceInfoMsg(ctx, status, true)
}

func prepareLispServiceInfoMsg(ctx *zedagentContext, status types.NetworkServiceStatus) {
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

	lispInfo := new(zmet.ZInfoLisp)
	lispStatus := status.LispInfoStatus
	if lispStatus != nil {
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
	log.Printf("XXXXX Publish LispInfo message to zedcloud\n")
	publishNetworkServiceInfo(ctx, serviceUUID, infoMsg)
}

func handleNetworkLispServiceStatusModify(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareLispServiceInfoMsg(ctx, status)
}

func handleNetworkLispServiceStatusDelete(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareLispServiceInfoMsg(ctx, status)
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
		publishNetworkServiceInfo(ctx, serviceUUID, infoMsg)
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

	// prapare the final stuff
	infoMsg.InfoContent = new(zmet.ZInfoMsg_Sinfo)
	if x, ok := infoMsg.GetInfoContent().(*zmet.ZInfoMsg_Sinfo); ok {
		x.Sinfo = svcInfo
	}
	publishNetworkServiceInfo(ctx, serviceUUID, infoMsg)
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

func publishNetworkServiceInfo(ctx *zedagentContext, serviceUUID string, infoMsg *zmet.ZInfoMsg) {
	publishNetworkServiceInfoToZedCloud(serviceUUID, infoMsg, ctx.iteration)
	ctx.iteration += 1
}

func publishNetworkServiceInfoToZedCloud(serviceUUID string, infoMsg *zmet.ZInfoMsg, iteration int) {
	if debug {
		log.Printf("publishNetworkServiceInfoToZedCloud sending %v\n", infoMsg)
	}
	log.Printf("publishNetworkServiceInfoToZedCloud sending %v\n", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishNetworkServiceInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := serverName + "/" + statusApi
	zedcloud.RemoveDeferred(serviceUUID)
	err = SendProtobuf(statusUrl, data, iteration)
	if err != nil {
		log.Printf("publishNetworkServiceInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(serviceUUID, data, statusUrl, zedcloudCtx,
			true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}

func createNetworkServiceMetrics(ctx *zedagentContext,
	reportMetrics *zmet.ZMetricMsg) {
	sub := ctx.subNetworkServiceStatus
	stlist := sub.GetAll()
	if stlist == nil || len(stlist) == 0 {
		return
	}
	for _, st := range stlist {
		status := cast.CastNetworkServiceStatus(st)
		metricService := protoEncodeNetworkServiceMetricProto(status)
		reportMetrics.Sm = append(reportMetrics.Sm, metricService)
	}
	if debug {
		log.Println("network service metrics: ",
			reportMetrics.Sm)
	}
}

func protoEncodeNetworkServiceMetricProto(status types.NetworkServiceStatus) *zmet.ZMetricService {

	serviceMetric := new(zmet.ZMetricService)
	serviceMetric.ServiceID = status.Key()
	serviceMetric.ServiceName = status.DisplayName
	serviceMetric.ServiceType = uint32(status.Type)
	switch status.Type {
	case types.NST_STRONGSWAN:
		protoEncodeVpnServiceMetric(status, serviceMetric)

	case types.NST_LISP:
		log.Printf("XXXXX Lisp Service Metric\n")
		protoEncodeLispServiceMetric(status, serviceMetric)
	}

	return serviceMetric
}

func protoEncodeLispServiceMetric(status types.NetworkServiceStatus,
	serviceMetric *zmet.ZMetricService) {
	if status.LispMetrics == nil {
		return
	}
	metrics := status.LispMetrics
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

func protoEncodeVpnServiceMetric(status types.NetworkServiceStatus,
	serviceMetric *zmet.ZMetricService) {
	if status.VpnStatus == nil {
		return
	}
	vpnStatus := status.VpnStatus
	vpnMetric := new(zmet.ZMetricVpn)
	vpnMetric.ConnStat = new(zmet.ZMetricConn)
	vpnMetric.ConnStat.InPkts = new(zmet.PktStat)
	vpnMetric.ConnStat.OutPkts = new(zmet.PktStat)
	for _, vpnConn := range vpnStatus.ActiveVpnConns {
		for _, linkData := range vpnConn.Links {
			vpnMetric.ConnStat.InPkts.Packets += linkData.LInfo.PktsCount
			vpnMetric.ConnStat.InPkts.Bytes += linkData.LInfo.BytesCount
			vpnMetric.ConnStat.OutPkts.Packets += linkData.RInfo.PktsCount
			vpnMetric.ConnStat.OutPkts.Bytes += linkData.RInfo.BytesCount
		}
	}
	serviceMetric.ServiceContent = new(zmet.ZMetricService_Vpnm)
	if x, ok := serviceMetric.GetServiceContent().(*zmet.ZMetricService_Vpnm); ok {
		x.Vpnm = vpnMetric
	}
}
