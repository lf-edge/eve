// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedagent

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
)

func handleNetworkObjectStatusModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Infof("handleNetworkObjectCreate(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkObjectStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleNetworkObjectStatusModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkObject error %s\n", status.Error)
	}
	prepareAndPublishNetworkInfoMsg(ctx, status, false)
	log.Infof("handleNetworkObjectStatusModify(%s) done\n", key)
}

func handleNetworkObjectStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkObjectStatusDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkObjectStatus(statusArg)
	prepareAndPublishNetworkInfoMsg(ctx, status, true)
	log.Infof("handleNetworkObjectStatusDelete(%s) done\n", key)
}

func prepareAndPublishNetworkInfoMsg(ctx *zedagentContext,
	status types.NetworkObjectStatus, deleted bool) {

	infoMsg := &zmet.ZInfoMsg{}
	infoType := new(zmet.ZInfoTypes)
	*infoType = zmet.ZInfoTypes_ZiNetworkObject
	infoMsg.DevId = *proto.String(zcdevUUID.String())
	infoMsg.Ztype = *infoType

	networkUUID := status.Key()
	netInfo := new(zmet.ZInfoNetworkObject)
	netInfo.NetworkID = networkUUID
	netInfo.NetworkType = uint32(status.Type)
	netInfo.DhcpType = uint32(status.Dhcp)
	netInfo.Subnet = status.Subnet.String()
	netInfo.Gateway = status.Gateway.String()
	netInfo.Domainname = status.DomainName
	netInfo.NtpServer = status.NtpServer.String()

	for _, ns := range status.DnsServers {
		netInfo.DnsServers = append(netInfo.DnsServers, ns.String())
	}
	if status.DhcpRange.Start != nil {
		netInfo.DhcpRangeLow = status.DhcpRange.Start.String()
	}
	if status.DhcpRange.End != nil {
		// XXX Should be High in API
		netInfo.DhcpRangeHugh = status.DhcpRange.End.String()
	}

	netInfo.BridgeNum = uint32(status.BridgeNum)
	netInfo.BridgeName = status.BridgeName
	netInfo.BridgeIPAddr = status.BridgeIPAddr

	for mac, ip := range status.IPAssignments {
		assignment := new(zmet.ZmetIPAssignmentEntry)
		assignment.MacAddress = mac
		assignment.IpAddress = append(assignment.IpAddress, ip.String())
		netInfo.IpAssignments = append(netInfo.IpAssignments,
			assignment)
	}
	for _, s := range status.BridgeIPSets {
		netInfo.BridgeIPSets = append(netInfo.BridgeIPSets, s)
	}
	for _, v := range status.VifNames {
		netInfo.VifNames = append(netInfo.VifNames, v)
	}
	netInfo.Ipv4Eid = status.Ipv4Eid

	if !status.ErrorTime.IsZero() {
		errInfo := new(zmet.ErrorInfo)
		errInfo.Description = status.Error
		errTime, _ := ptypes.TimestampProto(status.ErrorTime)
		errInfo.Timestamp = errTime
		netInfo.NetworkErr = append(netInfo.NetworkErr, errInfo)
	}

	log.Debugf("Publish Network Info message to zedcloud: %v\n", infoMsg)
	publishInfo(ctx, networkUUID, infoMsg)
}
