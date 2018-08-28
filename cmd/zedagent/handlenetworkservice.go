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

// we may need to post multiple Vpn messages
func handleNetworkVpnServiceStatusModify(ctx *zedagentContext,
	status types.NetworkServiceStatus) {
	prepareVpnServiceInfoMsg(ctx, status, false)
}

func handleNetworkVpnServiceStatusDelete(ctx *zedagentContext, status types.NetworkServiceStatus) {
	prepareVpnServiceInfoMsg(ctx, status, true)
}

func handleNetworkLispServiceStatusModify(ctx *zedagentContext, status types.NetworkServiceStatus) {
	// XXX, fill in Lisp Details

}

func handleNetworkLispServiceStatusDelete(ctx *zedagentContext, status types.NetworkServiceStatus) {
	// XXX, fill in Lisp Details
}

func prepareVpnServiceInfoMsg(ctx *zedagentContext, status types.NetworkServiceStatus, delete bool) {
	published := false
	infoMsg := &zmet.ZInfoMsg{}
	infoType := new(zmet.ZInfoTypes)
	// XXX:define in api zmet proto
	//*infoType = zmet.ZInfoTypes_ZiService
	*infoType = zmet.ZInfoTypes_ZiHypervisor
	infoMsg.DevId = *proto.String(zcdevUUID.String())
	infoMsg.Ztype = *infoType

	vpnStatus := status.VpnStatus
	svcInfo := new(zmet.ZInfoService)
	svcInfo.ServiceID = status.Key()
	svcInfo.ServiceName = status.DisplayName
	svcInfo.ServiceType = uint32(status.Type)
	svcInfo.SoftwareList = new(zmet.ZInfoSW)
	svcInfo.SoftwareList.SwVersion = vpnStatus.Version
	upTime, _ := ptypes.TimestampProto(vpnStatus.UpTime)
	svcInfo.UpTime = upTime
	if !status.ErrorTime.IsZero() {
		errInfo := new(zmet.ErrorInfo)
		errInfo.Description = status.Error
		errTime, _ := ptypes.TimestampProto(status.ErrorTime)
		errInfo.Timestamp = errTime
		svcInfo.SvcErr = append(svcInfo.SvcErr, errInfo)
	}

	// stale connections
	for _, vpnConn := range vpnStatus.StaleVpnConns {
		publishVpnConnection(ctx, vpnStatus, vpnConn, infoMsg, svcInfo)
		published = true
	}
	// active connections
	for _, vpnConn := range vpnStatus.ActiveVpnConns {
		publishVpnConnection(ctx, vpnStatus, vpnConn, infoMsg, svcInfo)
		published = true
	}

	// if nothing published, publish summary
	if published == false {
		publishNetworkServiceInfo(ctx, infoMsg)
	}
}

func publishVpnConnection(ctx *zedagentContext,
	vpnStatus types.ServiceVpnStatus, vpnConn types.VpnConnStatus,
	infoMsg *zmet.ZInfoMsg, svcInfo *zmet.ZInfoService) {

	vpnInfo := new(zmet.ZInfoVpn)
	vpnInfo.Id = vpnConn.Id
	vpnInfo.Name = vpnConn.Name
	vpnInfo.IkeProposals = vpnConn.Ikes
	vpnInfo.State = zmet.ZInfoVpnState(vpnConn.State)
	vpnInfo.ListeningIpAddrs = make([]string, 1)
	vpnInfo.ListeningIpAddrs[0] = vpnStatus.IpAddrs

	vpnConnInfo := new(zmet.ZInfoVpnConn)
	vpnConnInfo.ReqId = vpnConn.ReqId
	vpnConnInfo.RouteTable = vpnStatus.RouteTable

	localLinkInfo := new(zmet.ZInfoVpnLink)
	localLinkInfo.IpAddr = vpnConn.LocalLink.IpAddr
	localLinkInfo.SubNet = vpnConn.LocalLink.SubNet
	localLinkInfo.SpiId = vpnConn.LocalLink.SpiId
	localLinkInfo.Direction = vpnConn.LocalLink.Direction

	remoteLinkInfo := new(zmet.ZInfoVpnLink)
	remoteLinkInfo.IpAddr = vpnConn.RemoteLink.IpAddr
	remoteLinkInfo.SubNet = vpnConn.RemoteLink.SubNet
	remoteLinkInfo.SpiId = vpnConn.RemoteLink.SpiId
	remoteLinkInfo.Direction = vpnConn.RemoteLink.Direction

	vpnConnInfo.Link = make([]*zmet.ZInfoVpnLink, 2)
	vpnConnInfo.Link[0] = localLinkInfo
	vpnConnInfo.Link[1] = remoteLinkInfo

	vpnInfo.Conn = make([]*zmet.ZInfoVpnConn, 1)
	vpnInfo.Conn[0] = vpnConnInfo

	svcInfo.InfoContent = new(zmet.ZInfoService_Vinfo)
	if x, ok := svcInfo.GetInfoContent().(*zmet.ZInfoService_Vinfo); ok {
		x.Vinfo = vpnInfo
	}

	// prapare the final stuff
	infoMsg.InfoContent = new(zmet.ZInfoMsg_Sinfo)
	if x, ok := infoMsg.GetInfoContent().(*zmet.ZInfoMsg_Sinfo); ok {
		x.Sinfo = svcInfo
	}
	publishNetworkServiceInfo(ctx, infoMsg)
}

func publishNetworkServiceInfo(ctx *zedagentContext, infoMsg *zmet.ZInfoMsg) {
	publishNetworkServiceInfoToZedCloud(infoMsg, ctx.iteration)
	ctx.iteration += 1
}

func publishNetworkServiceInfoToZedCloud(infoMsg *zmet.ZInfoMsg, iteration int) {
	if debug {
		log.Printf("publishServiceInfoToZedCloud sending %v\n", infoMsg)
	}
	log.Printf("publishServiceInfoToZedCloud sending %v\n", infoMsg)
	data, err := proto.Marshal(infoMsg)
	if err != nil {
		log.Fatal("publishServiceInfoToZedCloud proto marshaling error: ", err)
	}
	deviceUUID := zcdevUUID.String()
	statusUrl := serverName + "/" + statusApi
	zedcloud.RemoveDeferred(deviceUUID)
	err = SendProtobuf(statusUrl, data, iteration)
	if err != nil {
		log.Printf("PublishDeviceInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(deviceUUID, data, statusUrl, zedcloudCtx,
			true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}
